//! PKCS#11 session management: session table, pending operations, async state.

use std::thread::JoinHandle;

use cryptoki_sys::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKS_RO_PUBLIC_SESSION, CKS_RW_PUBLIC_SESSION,
    CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE,
};

use zeroize::Zeroizing;

use crate::ck32::{CKF_ASYNC_SESSION, CK_ASYNC_ID};
use crate::mechanism::SignMechanism;

/// The result of an async background operation.
#[derive(Debug)]
pub enum AsyncResult {
    /// The operation produced a signature or decrypt result.
    Bytes(Vec<u8>),
    /// The user did not press the button in time.
    Rejected,
    /// Device returned an error.
    DeviceError(String),
}

/// State of any pending (Sign/Decrypt) operation on a session.
pub enum PendingOp {
    /// No operation in progress.
    None,
    /// A sign operation that has been init'd but not yet executed.
    SignReady {
        key_handle: CK_OBJECT_HANDLE,
        mechanism: SignMechanism,
        /// Accumulated data from C_SignUpdate calls. Zeroed on drop.
        accumulator: Zeroizing<Vec<u8>>,
    },
    /// A digest operation that has been init'd (multi-part C_DigestUpdate flow).
    DigestReady {
        mechanism: CK_MECHANISM_TYPE,
        /// Accumulated data from C_DigestUpdate calls. Zeroed on drop.
        accumulator: Zeroizing<Vec<u8>>,
    },
    /// A decrypt operation that has been init'd but not yet executed.
    DecryptReady { key_handle: CK_OBJECT_HANDLE },
    /// An async background thread is running.
    Async {
        id: CK_ASYNC_ID,
        thread: JoinHandle<AsyncResult>,
    },
    /// The async thread has been joined (e.g. by C_AsyncJoin) but the result
    /// has not yet been consumed by C_AsyncComplete.
    AsyncCompleted(AsyncResult),
}

impl std::fmt::Debug for PendingOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PendingOp::None => write!(f, "None"),
            PendingOp::SignReady {
                key_handle,
                mechanism,
                accumulator,
            } => {
                write!(
                    f,
                    "SignReady {{ key={}, mech={:?}, acc_len={} }}",
                    key_handle,
                    mechanism,
                    accumulator.len()
                )
            }
            PendingOp::DigestReady {
                mechanism,
                accumulator,
            } => {
                write!(
                    f,
                    "DigestReady {{ mech={:#x}, acc_len={} }}",
                    mechanism,
                    accumulator.len()
                )
            }
            PendingOp::DecryptReady { key_handle } => {
                write!(f, "DecryptReady {{ key={} }}", key_handle)
            }
            PendingOp::Async { id, .. } => write!(f, "Async {{ id={} }}", id),
            PendingOp::AsyncCompleted(_) => write!(f, "AsyncCompleted"),
        }
    }
}

/// Whether a session was opened as async or sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Sync,
    Async,
}

/// A single PKCS#11 session.
pub struct Session {
    pub handle: CK_SESSION_HANDLE,
    pub session_type: SessionType,
    pub flags: cryptoki_sys::CK_FLAGS,
    /// Pending operation state.
    pub pending: PendingOp,
    /// Handles queued from C_FindObjectsInit, drained by C_FindObjects.
    pub find_results: Vec<CK_OBJECT_HANDLE>,
    /// Monotonically increasing async operation ID.
    next_async_id: CK_ASYNC_ID,
}

impl Session {
    fn new(handle: CK_SESSION_HANDLE, flags: cryptoki_sys::CK_FLAGS) -> Self {
        let session_type = if flags & CKF_ASYNC_SESSION != 0 {
            SessionType::Async
        } else {
            SessionType::Sync
        };
        Session {
            handle,
            session_type,
            flags,
            pending: PendingOp::None,
            find_results: Vec::new(),
            next_async_id: 1,
        }
    }

    /// Allocate a fresh async operation ID.
    pub fn next_async_id(&mut self) -> CK_ASYNC_ID {
        let id = self.next_async_id;
        self.next_async_id += 1;
        id
    }

    /// Return the `CK_SESSION_INFO.state` value.
    pub fn state(&self) -> u64 {
        if self.flags & CKF_RW_SESSION != 0 {
            CKS_RW_PUBLIC_SESSION
        } else {
            CKS_RO_PUBLIC_SESSION
        }
    }
}

/// The global session table.
///
/// Session handles are assigned monotonically starting at 1.
pub struct SessionTable {
    sessions: Vec<Session>,
    next_handle: CK_SESSION_HANDLE,
}

impl SessionTable {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_handle: 1,
        }
    }

    /// Open a new session, returning its handle.
    pub fn open(&mut self, flags: cryptoki_sys::CK_FLAGS) -> CK_SESSION_HANDLE {
        // PKCS#11 requires CKF_SERIAL_SESSION to always be set.
        let flags = flags | CKF_SERIAL_SESSION;
        let handle = self.next_handle;
        self.next_handle += 1;
        self.sessions.push(Session::new(handle, flags));
        handle
    }

    /// Close a session by handle. Returns `true` if found and removed.
    pub fn close(&mut self, handle: CK_SESSION_HANDLE) -> bool {
        if let Some(pos) = self.sessions.iter().position(|s| s.handle == handle) {
            self.sessions.remove(pos);
            true
        } else {
            false
        }
    }

    /// Close all sessions.
    pub fn close_all(&mut self) {
        self.sessions.clear();
    }

    /// Retrieve a mutable reference to a session by handle.
    pub fn get_mut(&mut self, handle: CK_SESSION_HANDLE) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|s| s.handle == handle)
    }

    /// Retrieve a shared reference to a session by handle.
    pub fn get(&self, handle: CK_SESSION_HANDLE) -> Option<&Session> {
        self.sessions.iter().find(|s| s.handle == handle)
    }

    /// Return the number of open sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Return `true` if there are no open sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_table_open_close() {
        let mut table = SessionTable::new();
        let h1 = table.open(CKF_RW_SESSION);
        let h2 = table.open(CKF_RW_SESSION);
        assert_ne!(h1, h2);
        assert_eq!(table.len(), 2);
        assert!(table.close(h1));
        assert_eq!(table.len(), 1);
        assert!(!table.close(h1)); // already closed
    }

    #[test]
    fn session_type_async_from_flag() {
        let mut table = SessionTable::new();
        let h = table.open(CKF_RW_SESSION | CKF_ASYNC_SESSION);
        let s = table.get(h).unwrap();
        assert_eq!(s.session_type, SessionType::Async);
    }

    #[test]
    fn session_type_sync_without_flag() {
        let mut table = SessionTable::new();
        let h = table.open(CKF_RW_SESSION);
        let s = table.get(h).unwrap();
        assert_eq!(s.session_type, SessionType::Sync);
    }

    #[test]
    fn async_id_increments() {
        let mut table = SessionTable::new();
        let h = table.open(CKF_RW_SESSION | CKF_ASYNC_SESSION);
        let s = table.get_mut(h).unwrap();
        let id1 = s.next_async_id();
        let id2 = s.next_async_id();
        assert_eq!(id2, id1 + 1);
    }

    #[test]
    fn close_all_clears_sessions() {
        let mut table = SessionTable::new();
        table.open(CKF_RW_SESSION);
        table.open(CKF_RW_SESSION);
        table.close_all();
        assert_eq!(table.len(), 0);
    }
}
