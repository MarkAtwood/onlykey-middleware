use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::Parser;

use onlykey_transport::challenge_ui::{ChallengeDisplay, ExecDisplay, StderrDisplay, TtyDisplay};
use onlykey_transport::config::ChallengeDisplayKind;
use onlykey_transport::{EccAlgorithm, OnlyKeyDevice};

use onlykey_vcard::apdu::{Apdu, RApdu};
use onlykey_vcard::applet::{Applet, OpenPgpApplet, PivApplet};
use onlykey_vcard::certstore::Certstore;
use onlykey_vcard::vpcd::{VpcdConnection, VpcdCtrl, VpcdMessage, VpcdState};

#[derive(clap::Parser)]
#[command(name = "onlykey-vcard", about = "OnlyKey virtual smartcard daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Applet(s) to serve.
    #[arg(long, value_enum, default_value = "both", global = true)]
    applet: AppletKind,
    /// TCP port for OpenPGP Card applet.
    #[arg(long, default_value_t = 35963, global = true)]
    port: u16,
    /// TCP port for PIV applet.
    #[arg(long, default_value_t = 35964, global = true)]
    piv_port: u16,
    /// Enable verbose logging to stderr.
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run the virtual smartcard daemon (default when no subcommand given).
    Run,
    /// Import a certificate from a PEM or DER file into the cert store.
    ImportCert {
        /// Slot name (e.g. piv-9A, piv-9C, piv-9D, piv-9E).
        #[arg(long)]
        slot: String,
        /// Path to PEM or DER certificate file.
        path: std::path::PathBuf,
    },
    /// List certificates stored in the cert store.
    ListCerts,
    /// Generate and store a self-signed certificate for a PIV slot.
    GenerateCert {
        /// Slot name (piv-9A, piv-9C, piv-9D, piv-9E).
        #[arg(long)]
        slot: String,
        /// Subject Common Name for the certificate.
        #[arg(long, default_value = "OnlyKey")]
        cn: String,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum AppletKind {
    Openpgp,
    Piv,
    Both,
}

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        None | Some(Command::Run) => run_daemon(&cli),
        Some(Command::ImportCert { slot, path }) => cmd_import_cert(slot, path, &cli),
        Some(Command::ListCerts) => cmd_list_certs(&cli),
        Some(Command::GenerateCert { slot, cn }) => cmd_generate_cert(slot, cn, &cli),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run_daemon(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Install SIGTERM / SIGINT handler. Without this, the process exits silently
    // on systemd stop, giving no indication that shutdown was clean. The handler
    // logs a message and exits. In-flight APDU operations are abandoned, which is
    // safe: the signature counter uses a batch+margin persistence scheme (see
    // openpgp.rs) so any uncommitted in-RAM increments are recovered on next start.
    // Issue OnlyKey-lubq.
    ctrlc::set_handler(|| {
        eprintln!("onlykey-vcard: received termination signal, exiting");
        std::process::exit(0);
    })
    .unwrap_or_else(|e| eprintln!("onlykey-vcard: warning: failed to install signal handler: {e}"));

    let config = match onlykey_transport::config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            // Failing open is safe: all defaults are conservative (no device path assumed,
            // standard challenge timeout). Log so the user knows the config was not applied.
            eprintln!("warning: failed to load config ({}), using defaults", e);
            onlykey_transport::config::Config::default()
        }
    };

    let display: Arc<dyn ChallengeDisplay> = make_display(&config.challenge_display);
    let timeout = config.challenge_timeout;

    eprintln!("Opening OnlyKey device...");
    let device = OnlyKeyDevice::open(config)?;
    eprintln!("Device opened: firmware {}", device.firmware_version);
    let pseudo_serial = device.pseudo_serial;
    let device = Arc::new(Mutex::new(device));

    let certstore = Certstore::open_default()?;
    let certstore = Arc::new(Mutex::new(certstore));

    let verbose = cli.verbose;

    let mut handles = Vec::new();

    match cli.applet {
        AppletKind::Openpgp | AppletKind::Both => {
            let listener = TcpListener::bind(("127.0.0.1", cli.port))?;
            eprintln!("OpenPGP Card applet listening on port {}", cli.port);
            let d = Arc::clone(&device);
            let c = Arc::clone(&certstore);
            let disp = Arc::clone(&display);
            handles.push(thread::spawn(move || {
                // Use with_serial so two devices with different keys are distinguishable
                // to gpg --card-status and other OpenPGP Card consumers.
                serve_applet(
                    listener,
                    move || OpenPgpApplet::with_serial(pseudo_serial),
                    d,
                    c,
                    disp,
                    timeout,
                    verbose,
                );
            }));
        }
        _ => {}
    }

    match cli.applet {
        AppletKind::Piv | AppletKind::Both => {
            let listener = TcpListener::bind(("127.0.0.1", cli.piv_port))?;
            eprintln!("PIV applet listening on port {}", cli.piv_port);
            let d = Arc::clone(&device);
            let c = Arc::clone(&certstore);
            let disp = Arc::clone(&display);
            handles.push(thread::spawn(move || {
                serve_applet(listener, PivApplet::new, d, c, disp, timeout, verbose);
            }));
        }
        _ => {}
    }

    for h in handles {
        let _ = h.join();
    }

    Ok(())
}

fn make_display(kind: &ChallengeDisplayKind) -> Arc<dyn ChallengeDisplay> {
    match kind {
        ChallengeDisplayKind::Tty => Arc::new(TtyDisplay),
        ChallengeDisplayKind::Stderr => Arc::new(StderrDisplay),
        ChallengeDisplayKind::Exec(cmd) => Arc::new(ExecDisplay(cmd.clone())),
    }
}

fn serve_applet<A, F>(
    listener: TcpListener,
    make_applet: F,
    device: Arc<Mutex<OnlyKeyDevice>>,
    certstore: Arc<Mutex<Certstore>>,
    display: Arc<dyn ChallengeDisplay>,
    timeout: Duration,
    verbose: bool,
) where
    A: Applet + 'static,
    F: Fn() -> A + Send + 'static,
{
    let conn_count = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_string());

        // Atomically acquire a connection slot. compare_exchange ensures we never
        // exceed MAX_CONNECTIONS even under concurrent accept() calls.
        const MAX_CONNECTIONS: usize = 4;
        let acquired = loop {
            let current = conn_count.load(Ordering::SeqCst);
            if current >= MAX_CONNECTIONS {
                break false;
            }
            if conn_count
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break true;
            }
        };
        if !acquired {
            eprintln!("connection limit reached, rejecting {}", peer);
            continue;
        }

        if verbose {
            eprintln!("connection from {}", peer);
        }

        let mut applet = make_applet();
        let d = Arc::clone(&device);
        let c = Arc::clone(&certstore);
        let disp = Arc::clone(&display);
        let counter = Arc::clone(&conn_count);

        thread::spawn(move || {
            handle_connection(&mut applet, stream, d, c, disp, timeout, verbose, &peer);
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_connection<A: Applet>(
    applet: &mut A,
    stream: TcpStream,
    device: Arc<Mutex<OnlyKeyDevice>>,
    certstore: Arc<Mutex<Certstore>>,
    display: Arc<dyn ChallengeDisplay>,
    timeout: Duration,
    verbose: bool,
    peer: &str,
) {
    let mut conn = VpcdConnection::new(stream);
    let _ = conn.set_read_timeout(Some(Duration::from_secs(300)));

    loop {
        let msg = match conn.read_message() {
            Ok(m) => m,
            Err(onlykey_vcard::vpcd::VpcdError::Closed) => {
                if verbose {
                    eprintln!("[{}] connection closed", peer);
                }
                return;
            }
            Err(onlykey_vcard::vpcd::VpcdError::ProtocolError(ref msg)) => {
                eprintln!("[{}] protocol error: {}", peer, msg);
                return;
            }
            Err(onlykey_vcard::vpcd::VpcdError::Io(ref e))
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                eprintln!("[{}] idle connection closed after timeout", peer);
                return;
            }
            Err(e) => {
                eprintln!("[{}] read error: {}", peer, e);
                return;
            }
        };

        match msg {
            VpcdMessage::Control(VpcdCtrl::Off) => {
                if verbose {
                    eprintln!("[{}] power off", peer);
                }
                conn.set_idle();
                applet.reset();
            }
            VpcdMessage::Control(VpcdCtrl::On) => {
                if verbose {
                    eprintln!("[{}] power on", peer);
                }
                conn.set_ready();
                applet.reset();
            }
            VpcdMessage::Control(VpcdCtrl::Reset) => {
                if verbose {
                    eprintln!("[{}] reset", peer);
                }
                conn.set_ready();
                applet.reset();
            }
            VpcdMessage::Control(VpcdCtrl::Atr) => {
                if verbose {
                    eprintln!("[{}] ATR request", peer);
                }
                if let Err(e) = conn.send_atr(applet.atr()) {
                    eprintln!("[{}] send_atr error: {}", peer, e);
                    return;
                }
            }
            VpcdMessage::UnknownCtrl(b) => {
                eprintln!(
                    "[{}] unknown vpcd control byte 0x{:02x}, closing connection",
                    peer, b
                );
                return;
            }
            VpcdMessage::Apdu(raw) => {
                if conn.state() == VpcdState::Idle {
                    eprintln!("[{}] APDU received before power-on/reset, rejecting", peer);
                    let rapdu = RApdu::conditions_not_satisfied();
                    let _ = conn.send_rapdu(&rapdu.as_bytes());
                    continue;
                }

                let apdu = match Apdu::parse(&raw) {
                    Ok(a) => a,
                    Err(e) => {
                        if verbose {
                            eprintln!("[{}] APDU parse error: {:?}", peer, e);
                        }
                        let rapdu = RApdu::wrong_length(0);
                        let _ = conn.send_rapdu(&rapdu.as_bytes());
                        continue;
                    }
                };

                if verbose {
                    eprintln!(
                        "[{}] APDU CLA={:02X} INS={:02X} P1={:02X} P2={:02X} data_len={}",
                        peer,
                        apdu.cla,
                        apdu.ins,
                        apdu.p1,
                        apdu.p2,
                        apdu.data.len()
                    );
                }

                let rapdu = {
                    // Recover from lock poisoning: a panic in another connection thread should not
                    // prevent other connections from proceeding. Each connection's state is independent.
                    let dev = device.lock().unwrap_or_else(|p| p.into_inner());
                    let mut cs = certstore.lock().unwrap_or_else(|p| p.into_inner());
                    applet.process(&apdu, &dev, display.as_ref(), timeout, &mut cs)
                };

                if verbose {
                    eprintln!(
                        "[{}] R-APDU SW={:02X}{:02X} data_len={}",
                        peer,
                        rapdu.sw1,
                        rapdu.sw2,
                        rapdu.data.len()
                    );
                }

                if let Err(e) = conn.send_rapdu(&rapdu.as_bytes()) {
                    eprintln!("[{}] send_rapdu error: {}", peer, e);
                    return;
                }

                if rapdu.sw1 == 0x61 {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
                } else {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(300)));
                }
            }
        }
    }
}

fn cmd_import_cert(slot: &str, path: &Path, _cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let der = onlykey_vcard::cert_file::load_cert_file(path)?;
    let certstore = Certstore::open_default()?;
    let label = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("imported");
    certstore.put_cert(slot, &der, label)?;
    println!("Imported certificate into slot '{}'", slot);
    Ok(())
}

fn cmd_list_certs(_cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let certstore = Certstore::open_default()?;
    let certs = certstore.list()?;
    if certs.is_empty() {
        println!("No certificates stored.");
    } else {
        println!("{:<12} LABEL", "SLOT");
        for (slot, label) in &certs {
            println!("{:<12} {}", slot, label);
        }
    }
    Ok(())
}

fn slot_name_to_params(slot: &str) -> Option<(u8, EccAlgorithm)> {
    match slot {
        "piv-9A" => Some((104, EccAlgorithm::NistP256)),
        "piv-9C" => Some((105, EccAlgorithm::NistP256)),
        "piv-9D" => Some((106, EccAlgorithm::Curve25519)),
        "piv-9E" => Some((107, EccAlgorithm::NistP256)),
        "openpgp-sig" => Some((101, EccAlgorithm::Ed25519)),
        "openpgp-aut" => Some((103, EccAlgorithm::Ed25519)),
        _ => None,
    }
}

fn cmd_generate_cert(slot: &str, cn: &str, _cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let (slot_num, algorithm) = slot_name_to_params(slot).ok_or_else(|| {
        format!(
            "unknown slot '{}'. Valid: piv-9A, piv-9C, piv-9D, piv-9E, openpgp-sig, openpgp-aut",
            slot
        )
    })?;

    if matches!(algorithm, EccAlgorithm::Curve25519) {
        return Err("Curve25519 key management slots do not use X.509 certificates".into());
    }

    let config = match onlykey_transport::config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            // Failing open is safe: all defaults are conservative (no device path assumed,
            // standard challenge timeout). Log so the user knows the config was not applied.
            eprintln!("warning: failed to load config ({}), using defaults", e);
            onlykey_transport::config::Config::default()
        }
    };
    let display = make_display(&config.challenge_display);
    let timeout = config.challenge_timeout;

    eprintln!("Opening OnlyKey device...");
    let device = OnlyKeyDevice::open(config)?;
    eprintln!(
        "Device opened. Generating certificate for slot '{}'...",
        slot
    );

    let der = onlykey_vcard::cert::generate_self_signed(
        slot,
        slot_num,
        algorithm,
        cn,
        b"250101000000Z",
        b"350101000000Z",
        &device,
        display.as_ref(),
        timeout,
    )?;

    let certstore = Certstore::open_default()?;
    certstore.put_cert(slot, &der, cn)?;
    println!(
        "Generated and stored self-signed certificate for slot '{}'",
        slot
    );
    Ok(())
}
