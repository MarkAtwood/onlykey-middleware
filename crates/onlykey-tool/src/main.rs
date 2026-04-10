use clap::Parser;

#[derive(clap::Parser)]
#[command(name = "onlykey-tool", about = "OnlyKey command-line utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Show device information and firmware version.
    DeviceInfo,
    /// Generate a default configuration file.
    GenerateConfig,
    /// Certificate management subcommands.
    Cert {
        #[command(subcommand)]
        action: CertCommand,
    },
}

#[derive(clap::Subcommand)]
enum CertCommand {
    /// List certificates stored in the cert store.
    List,
    /// Import a PEM or DER certificate into the cert store.
    Import {
        /// Slot name (e.g. piv-9A, piv-9C, piv-9D, piv-9E).
        #[arg(long)]
        slot: String,
        /// Path to PEM or DER certificate file.
        path: std::path::PathBuf,
    },
    /// Generate and store a self-signed certificate for a slot.
    Generate {
        /// Slot name (piv-9A, piv-9C, piv-9D, piv-9E).
        #[arg(long)]
        slot: String,
        /// Subject Common Name for the certificate.
        #[arg(long, default_value = "OnlyKey")]
        cn: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::DeviceInfo => cmd_device_info(),
        Command::GenerateConfig => cmd_generate_config(),
        Command::Cert { action } => cmd_cert(action),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_device_info() -> Result<(), Box<dyn std::error::Error>> {
    use onlykey_transport::{OnlyKeyDevice, TransportError};

    let config = onlykey_transport::config::Config::load().unwrap_or_default();

    match OnlyKeyDevice::open(config) {
        Ok(device) => {
            println!("state: unlocked");
            println!("firmware: {}", device.firmware_version);
        }
        Err(TransportError::Locked) => {
            println!("state: locked");
            println!("(connect and unlock your OnlyKey, then re-run)");
            return Ok(());
        }
        Err(TransportError::NotFound) => {
            return Err("no OnlyKey device found".into());
        }
        Err(e) => return Err(e.into()),
    }

    let slots_path = dirs::config_dir().map(|d| d.join("onlykey/slots.toml"));
    if let Some(path) = slots_path {
        if path.exists() {
            println!("slots.toml: {}", path.display());
            if let Ok(text) = std::fs::read_to_string(&path) {
                let count = text
                    .lines()
                    .filter(|l| {
                        l.trim().starts_with(|c: char| c.is_ascii_digit()) && l.contains('=')
                    })
                    .count();
                println!("configured slots: {}", count);
            }
        } else {
            println!("slots.toml: not found (run 'onlykey-tool generate-config' to create one)");
        }
    }

    Ok(())
}

fn cmd_generate_config() -> Result<(), Box<dyn std::error::Error>> {
    use onlykey_hid::{Command, HidFrame};
    use onlykey_transport::OnlyKeyDevice;

    let config = onlykey_transport::config::Config::load().unwrap_or_default();
    let device = OnlyKeyDevice::open(config)?;

    eprintln!("Probing key slots...");

    let mut ecc_lines: Vec<String> = Vec::new();
    let mut rsa_lines: Vec<String> = Vec::new();

    for slot_num in 101u8..=116 {
        let frame = match HidFrame::command(Command::GetPubkey.wire_byte(), slot_num, &[]) {
            Ok(f) => f,
            Err(_) => continue,
        };
        device.io.write(&frame)?;
        let response = device.io.read_until_idle(200)?;
        if response.is_error() {
            eprintln!("  ECC slot {}: empty", slot_num);
            continue;
        }
        let bytes = response.as_bytes();
        let algorithm = match onlykey_transport::detect_ecc_algorithm(bytes) {
            Some(alg) => alg,
            None if bytes.is_empty() => {
                eprintln!("  ECC slot {}: empty", slot_num);
                continue;
            }
            None => {
                eprintln!(
                    "  ECC slot {}: unexpected response length {}",
                    slot_num,
                    bytes.len()
                );
                continue;
            }
        };
        let alg_str = match algorithm {
            onlykey_transport::EccAlgorithm::Ed25519 => "ed25519",
            onlykey_transport::EccAlgorithm::Curve25519 => "curve25519",
            onlykey_transport::EccAlgorithm::NistP256 => "nistp256",
            onlykey_transport::EccAlgorithm::Secp256k1 => "secp256k1",
        };
        // 32-byte Ed25519 detection is uncertain: ~50% of Curve25519
        // u-coordinates pass wolfcrypt's Edwards curve check (see OnlyKey-6o9).
        // 32-byte Curve25519, and all 64-byte results, are reliable.
        let uncertain = bytes.len() == 32
            && algorithm == onlykey_transport::EccAlgorithm::Ed25519;
        eprintln!(
            "  ECC slot {}: {} bytes -> {}{}",
            slot_num,
            bytes.len(),
            alg_str,
            if uncertain { " (uncertain)" } else { " (auto-detected)" }
        );
        if uncertain {
            // Failure to pass check_key() is definitive (→ curve25519), but
            // success is not: ~50% of Curve25519 u-coordinates also pass.
            // If this slot is for ECDH / key-agreement, change to "curve25519".
            ecc_lines.push(format!(
                "{} = {:?} # uncertain: if ECDH/key-agreement slot, change to \"curve25519\"",
                slot_num, alg_str
            ));
        } else {
            ecc_lines.push(format!("{} = {:?} # auto-detected", slot_num, alg_str));
        }
    }

    for slot_num in 1u8..=4 {
        let frame = match HidFrame::command(Command::GetPubkey.wire_byte(), slot_num, &[]) {
            Ok(f) => f,
            Err(_) => continue,
        };
        device.io.write(&frame)?;
        let response = device.io.read_until_idle(200)?;
        if response.is_error() {
            eprintln!("  RSA slot {}: empty", slot_num);
            continue;
        }
        let len = response.as_bytes().len();
        let algorithm = match len {
            256 => "rsa2048",
            512 => "rsa4096",
            0 => {
                eprintln!("  RSA slot {}: empty", slot_num);
                continue;
            }
            _ => {
                eprintln!(
                    "  RSA slot {}: unexpected response length {}",
                    slot_num, len
                );
                continue;
            }
        };
        eprintln!("  RSA slot {}: {} bytes -> {}", slot_num, len, algorithm);
        rsa_lines.push(format!("{} = {:?}", slot_num, algorithm));
    }

    let out_path = dirs::config_dir()
        .ok_or("cannot determine config directory")?
        .join("onlykey/slots.toml");

    if out_path.exists() {
        eprintln!(
            "WARNING: {} already exists, writing to stdout instead",
            out_path.display()
        );
        print_slots_toml(&ecc_lines, &rsa_lines);
    } else {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut content = String::new();
        append_slots_toml(&mut content, &ecc_lines, &rsa_lines);
        // Write atomically: write to a temp file then rename into place.
        // rename() is atomic on POSIX when src and dst are on the same filesystem,
        // so a concurrent reader never sees a partial file.
        let tmp_path = out_path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, &content)?;
        std::fs::rename(&tmp_path, &out_path)?;
        eprintln!("Written to {}", out_path.display());
    }

    Ok(())
}

fn print_slots_toml(ecc_lines: &[String], rsa_lines: &[String]) {
    let mut s = String::new();
    append_slots_toml(&mut s, ecc_lines, rsa_lines);
    print!("{}", s);
}

fn append_slots_toml(out: &mut String, ecc_lines: &[String], rsa_lines: &[String]) {
    if !ecc_lines.is_empty() {
        out.push_str("[ecc]\n");
        for line in ecc_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    if !rsa_lines.is_empty() {
        out.push_str("[rsa]\n");
        for line in rsa_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    if ecc_lines.is_empty() && rsa_lines.is_empty() {
        out.push_str("# No keys found. Load keys onto your OnlyKey and re-run.\n");
        out.push_str("[ecc]\n");
        out.push_str("[rsa]\n");
    }
}

fn cmd_cert(action: CertCommand) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        CertCommand::List => cmd_cert_list(),
        CertCommand::Import { slot, path } => cmd_cert_import(&slot, &path),
        CertCommand::Generate { slot, cn } => cmd_cert_generate(&slot, &cn),
    }
}

fn cmd_cert_list() -> Result<(), Box<dyn std::error::Error>> {
    let certstore = onlykey_vcard::certstore::Certstore::open_default()?;
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

fn cmd_cert_import(slot: &str, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let der = onlykey_vcard::cert_file::load_cert_file(path)?;
    let certstore = onlykey_vcard::certstore::Certstore::open_default()?;
    let label = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("imported");
    certstore.put_cert(slot, &der, label)?;
    println!("Imported certificate into slot '{}'", slot);
    Ok(())
}

fn cmd_cert_generate(slot: &str, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (slot_num, algorithm) = slot_name_to_params(slot).ok_or_else(|| {
        format!(
            "unknown slot '{}'. Valid: piv-9A, piv-9C, piv-9D, piv-9E, openpgp-sig, openpgp-aut",
            slot
        )
    })?;

    let config = onlykey_transport::config::Config::load().unwrap_or_default();
    let timeout = config.challenge_timeout;

    eprintln!("Opening OnlyKey device...");
    let device = onlykey_transport::OnlyKeyDevice::open(config)?;
    eprintln!(
        "Device opened. Generating certificate for slot '{}'...",
        slot
    );

    let display = onlykey_transport::challenge_ui::StderrDisplay;

    let der = onlykey_vcard::cert::generate_self_signed(
        slot,
        slot_num,
        algorithm,
        cn,
        b"250101000000Z",
        b"350101000000Z",
        &device,
        &display,
        timeout,
    )?;

    let certstore = onlykey_vcard::certstore::Certstore::open_default()?;
    certstore.put_cert(slot, &der, cn)?;
    println!(
        "Generated and stored self-signed certificate for slot '{}'",
        slot
    );
    Ok(())
}

fn slot_name_to_params(slot: &str) -> Option<(u8, onlykey_transport::EccAlgorithm)> {
    use onlykey_transport::EccAlgorithm;
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
