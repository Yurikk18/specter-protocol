//! OS-level memory hardening for decrypted wallet secrets.
//!
//! Provides a `LockedBytes` wrapper that:
//!
//! - Locks pages into physical memory so they cannot be swapped to disk
//!   (`mlock` on Unix, `VirtualLock` on Windows).
//! - Disables core dumps for the current process (Unix only) so an
//!   unintended crash cannot persist decrypted secrets to `core.*`.
//! - Zeroizes the buffer and unlocks on drop.
//!
//! This is "best-effort defense in depth": if `mlock`/`VirtualLock` are
//! unavailable (insufficient privileges, RLIMIT_MEMLOCK too small, etc.)
//! the wrapper still works but only provides heap allocation + zeroize.
//! The failure is logged once to stderr so operators can raise
//! `ulimit -l` if they care.
//!
//! # Platform notes
//!
//! - **Linux/macOS**: uses raw `libc::mlock`/`libc::munlock` on the
//!   `Vec<u8>` backing buffer. `libc` is a direct dep only when the
//!   `mlock` feature is enabled — otherwise the module compiles as a
//!   no-op wrapper so platforms without `libc` bindings still work.
//! - **Windows**: uses `VirtualLock`/`VirtualUnlock` via a minimal
//!   extern declaration (no `winapi` dep).
//! - **Other (WASM, embedded)**: no-op; the buffer still zeroizes on drop.

use zeroize::Zeroize;

/// A heap-allocated byte buffer whose pages are locked into physical
/// memory and zeroized on drop.
pub struct LockedBytes {
    data: Vec<u8>,
    locked: bool,
}

impl LockedBytes {
    /// Allocate `len` zero bytes and attempt to lock them into memory.
    pub fn new(len: usize) -> Self {
        let data = vec![0u8; len];
        let locked = try_lock(&data);
        Self { data, locked }
    }

    /// Take ownership of an existing buffer and attempt to lock it.
    pub fn from_vec(v: Vec<u8>) -> Self {
        let locked = try_lock(&v);
        Self { data: v, locked }
    }

    /// Immutable view of the locked bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Mutable view of the locked bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Whether the pages were successfully locked in physical memory.
    /// `false` means allocation succeeded but locking failed (e.g.,
    /// insufficient privileges); the bytes still zeroize on drop.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Length of the underlying buffer in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            try_unlock(&self.data);
        }
    }
}

impl std::fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedBytes")
            .field("len", &self.data.len())
            .field("locked", &self.locked)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Disable core dumps for the current process. Must be called once at
/// program startup BEFORE any sensitive data is loaded. On platforms
/// without the concept of core dumps (Windows, WASM), this is a no-op.
///
/// Returns `true` if the operation succeeded or was a no-op.
pub fn disable_core_dumps() -> bool {
    disable_core_dumps_impl()
}

// ─── Platform implementations ──────────────────────────────────────────

#[cfg(all(unix, feature = "memory-guard"))]
fn try_lock(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // SAFETY: the pointer is valid for the full length of `data`, which
    // is a Rust-owned Vec<u8>. `mlock` never writes, only pins pages.
    let rc = unsafe { libc::mlock(data.as_ptr() as *const _, data.len()) };
    if rc != 0 {
        log_mlock_failure();
        false
    } else {
        true
    }
}

#[cfg(all(unix, feature = "memory-guard"))]
fn try_unlock(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    unsafe {
        libc::munlock(data.as_ptr() as *const _, data.len());
    }
}

#[cfg(all(unix, feature = "memory-guard"))]
fn disable_core_dumps_impl() -> bool {
    use libc::{rlimit, setrlimit, RLIMIT_CORE};
    let rlim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { setrlimit(RLIMIT_CORE, &rlim) == 0 }
}

#[cfg(all(windows, feature = "memory-guard"))]
fn try_lock(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    extern "system" {
        fn VirtualLock(address: *mut core::ffi::c_void, size: usize) -> i32;
    }
    let rc = unsafe { VirtualLock(data.as_ptr() as *mut _, data.len()) };
    if rc == 0 {
        log_mlock_failure();
        false
    } else {
        true
    }
}

#[cfg(all(windows, feature = "memory-guard"))]
fn try_unlock(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    extern "system" {
        fn VirtualUnlock(address: *mut core::ffi::c_void, size: usize) -> i32;
    }
    unsafe {
        VirtualUnlock(data.as_ptr() as *mut _, data.len());
    }
}

#[cfg(all(windows, feature = "memory-guard"))]
fn disable_core_dumps_impl() -> bool {
    // Windows dumps are governed by WER (Windows Error Reporting) and
    // cannot be disabled per-process without registry changes. Document
    // this and return true (no-op).
    true
}

// Fallback: no feature flag, or unknown platform → silent no-op.
#[cfg(not(feature = "memory-guard"))]
fn try_lock(_: &[u8]) -> bool {
    false
}

#[cfg(not(feature = "memory-guard"))]
fn try_unlock(_: &[u8]) {}

#[cfg(not(feature = "memory-guard"))]
fn disable_core_dumps_impl() -> bool {
    true
}

// Also provide a fallback for "memory-guard feature enabled but
// platform is neither unix nor windows" (e.g. wasm32) so compilation
// never fails.
#[cfg(all(feature = "memory-guard", not(any(unix, windows))))]
fn try_lock(_: &[u8]) -> bool {
    false
}
#[cfg(all(feature = "memory-guard", not(any(unix, windows))))]
fn try_unlock(_: &[u8]) {}
#[cfg(all(feature = "memory-guard", not(any(unix, windows))))]
fn disable_core_dumps_impl() -> bool {
    true
}

#[cfg(feature = "memory-guard")]
fn log_mlock_failure() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "warning: memory lock failed — raise RLIMIT_MEMLOCK or run with CAP_IPC_LOCK \
             for full wallet-secret protection. Proceeding with zeroize-only guard."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_bytes_basic() {
        let mut lb = LockedBytes::new(64);
        assert_eq!(lb.len(), 64);
        assert!(!lb.is_empty());
        lb.as_mut_slice()[0] = 0xAA;
        assert_eq!(lb.as_slice()[0], 0xAA);
    }

    #[test]
    fn test_locked_bytes_from_vec() {
        let source = vec![1u8, 2, 3, 4, 5];
        let lb = LockedBytes::from_vec(source);
        assert_eq!(lb.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_locked_bytes_drop_zeroizes() {
        // We can't directly observe post-drop memory in safe Rust, but
        // we can confirm that ownership transfer works and no UB occurs.
        let lb = LockedBytes::new(32);
        drop(lb);
    }

    #[test]
    fn test_locked_bytes_empty() {
        let lb = LockedBytes::new(0);
        assert!(lb.is_empty());
        // Empty buffers should not attempt to lock (no-op branch).
    }

    #[test]
    fn test_disable_core_dumps_no_panic() {
        // May succeed or fail depending on platform + privileges, but
        // must never panic.
        let _ = disable_core_dumps();
    }
}
