//! Nullifier system for double-spend detection.
//!
//! Each token has a unique nullifier derived from the owner's secret and the token ID.
//! When a token is spent, its nullifier is published. If the same nullifier appears
//! twice, double-spend is detected and the blame protocol can identify the cheater.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Compute a nullifier from an owner's secret and a token ID.
///
/// nullifier = SHAKE-256("specter-nullifier:" || secret || token_id)
///
/// The nullifier is deterministic: the same secret + token_id always produces
/// the same nullifier. But given only the nullifier, the secret and token_id
/// cannot be recovered.
pub fn compute_nullifier(secret: &[u8; 32], token_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"specter-nullifier:");
    hasher.update(secret);
    hasher.update(token_id);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    XofReader::read(&mut reader, &mut output);
    output
}

/// A set of spent nullifiers for double-spend detection.
///
/// In a full system, this would be a distributed append-only log
/// maintained by the BFT consensus layer. For the prototype, it's
/// an in-memory HashSet with optional file-backed persistence.
///
/// When created with [`NullifierSet::with_file`], nullifiers are persisted
/// to an append-only binary file (concatenated 32-byte entries, no header).
/// On startup the file is read to reconstruct the set, so nullifiers
/// survive process restarts.
#[derive(Debug)]
pub struct NullifierSet {
    nullifiers: HashSet<[u8; 32]>,
    file: Option<File>,
}

impl NullifierSet {
    /// Create an empty in-memory nullifier set (no persistence).
    pub fn new() -> Self {
        Self {
            nullifiers: HashSet::new(),
            file: None,
        }
    }

    /// Create a file-backed nullifier set.
    ///
    /// If the file already exists its contents are loaded to reconstruct
    /// the set. New nullifiers are appended to the file on [`insert`](Self::insert).
    /// The file format is a sequence of concatenated 32-byte entries with no header.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened/created, or if the
    /// existing file size is not a multiple of 32.
    pub fn with_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();

        // Reject path traversal components for security
        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path traversal (..) not allowed in nullifier file path",
                ));
            }
        }

        // Open for reading + appending, creating if it does not exist.
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;

        // Check file size before reading (prevent OOM from huge files)
        const MAX_NULLIFIER_FILE_SIZE: u64 = 32 * 10_000_000; // ~320MB, 10M nullifiers
        let metadata = file.metadata()?;
        if metadata.len() > MAX_NULLIFIER_FILE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("nullifier file too large: {} bytes", metadata.len()),
            ));
        }

        // Read existing contents to reconstruct the set.
        let mut buf = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut buf)?;

        if buf.len() % 32 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "nullifier file has invalid size {} (not a multiple of 32)",
                    buf.len()
                ),
            ));
        }

        let mut nullifiers = HashSet::with_capacity(buf.len() / 32);
        for chunk in buf.chunks_exact(32) {
            let mut entry = [0u8; 32];
            entry.copy_from_slice(chunk);
            nullifiers.insert(entry);
        }

        Ok(Self {
            nullifiers,
            file: Some(file),
        })
    }

    /// Insert a nullifier. Returns `true` if the nullifier was new (valid spend).
    /// Returns `false` if the nullifier was already present (double-spend detected).
    ///
    /// When file-backed, the nullifier is durably written to disk BEFORE being
    /// accepted into the in-memory set. If disk write fails, the spend is rejected.
    /// This prevents double-spend after crash (write-before-accept pattern).
    pub fn insert(&mut self, nullifier: [u8; 32]) -> bool {
        // Check in-memory first (fast path for duplicates)
        if self.nullifiers.contains(&nullifier) {
            return false; // already known
        }
        // Write to durable storage BEFORE in-memory insert.
        // If the process crashes after fsync but before HashSet insert,
        // the nullifier is recovered from file on restart (false positive
        // on one retry, which is safe — user retries the spend).
        if let Some(ref mut file) = self.file {
            if let Err(e) = file.write_all(&nullifier)
                .and_then(|_| file.flush())
                .and_then(|_| file.sync_all())
            {
                eprintln!("ERROR: failed to persist nullifier to disk: {}", e);
                return false; // Reject spend if we cannot durably record it
            }
        }
        self.nullifiers.insert(nullifier)
    }

    /// Check if a nullifier has been spent.
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Number of spent nullifiers.
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper around [`NullifierSet`].
///
/// All operations take `&self` and internally lock a [`Mutex`], so this
/// handle is `Clone + Send + Sync`. Cloning yields another handle sharing
/// the same underlying set.
///
/// Use this variant in multi-threaded deployments (BFT validators, async
/// gossip handlers, REST mint services). Single-threaded callers can
/// continue to use [`NullifierSet`] directly for zero-overhead access.
///
/// # Atomicity
///
/// `insert` takes the lock, checks membership, appends to the durable
/// file (if any), and updates the in-memory set — all inside a single
/// critical section. Two concurrent spenders of the same token race into
/// `insert` and exactly one sees the new nullifier; the other sees a
/// double-spend reject. The file-backed `write → flush → sync_all` runs
/// under the lock so a crash between fsync and map update cannot leave
/// the file diverged from the set.
#[derive(Clone, Debug)]
pub struct ConcurrentNullifierSet {
    inner: Arc<Mutex<NullifierSet>>,
}

impl ConcurrentNullifierSet {
    /// Wrap an existing [`NullifierSet`] behind a shared lock.
    pub fn new(set: NullifierSet) -> Self {
        Self { inner: Arc::new(Mutex::new(set)) }
    }

    /// Create an empty in-memory concurrent set.
    pub fn empty() -> Self {
        Self::new(NullifierSet::new())
    }

    /// File-backed concurrent constructor.
    pub fn with_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        NullifierSet::with_file(path).map(Self::new)
    }

    /// Atomic check-and-insert. Returns `true` on first spend, `false`
    /// on double-spend. A poisoned mutex (panic while another thread
    /// held the lock) is recovered by reading the inner data — the set
    /// is append-only so recovery is safe.
    pub fn insert(&self, nullifier: [u8; 32]) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(nullifier)
    }

    /// Check-only membership lookup.
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.contains(nullifier)
    }

    /// Number of spent nullifiers under the lock.
    pub fn len(&self) -> usize {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.len()
    }

    /// Whether the set is empty under the lock.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ConcurrentNullifierSet {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_nullifier_deterministic(secret: [u8; 32], token_id: [u8; 32]) {
            let n1 = compute_nullifier(&secret, &token_id);
            let n2 = compute_nullifier(&secret, &token_id);
            prop_assert_eq!(n1, n2);
        }

        #[test]
        fn prop_nullifier_collision_resistant(
            s1: [u8; 32], s2: [u8; 32], t1: [u8; 32], t2: [u8; 32]
        ) {
            // Distinct inputs → distinct outputs (with overwhelming probability).
            if (s1, t1) != (s2, t2) {
                prop_assert_ne!(
                    compute_nullifier(&s1, &t1),
                    compute_nullifier(&s2, &t2)
                );
            }
        }

        #[test]
        fn prop_nullifier_set_membership_matches_hashset(
            inserts in proptest::collection::vec(any::<[u8; 32]>(), 0..64)
        ) {
            let mut set = NullifierSet::new();
            let mut reference = std::collections::HashSet::new();
            for n in &inserts {
                let first_seen = reference.insert(*n);
                let inserted = set.insert(*n);
                prop_assert_eq!(first_seen, inserted);
            }
            prop_assert_eq!(set.len(), reference.len());
        }
    }

    #[test]
    fn test_nullifier_deterministic() {
        let secret = [1u8; 32];
        let token_id = [2u8; 32];
        let n1 = compute_nullifier(&secret, &token_id);
        let n2 = compute_nullifier(&secret, &token_id);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_different_secrets_different_nullifiers() {
        let token_id = [0u8; 32];
        let n1 = compute_nullifier(&[1u8; 32], &token_id);
        let n2 = compute_nullifier(&[2u8; 32], &token_id);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_different_tokens_different_nullifiers() {
        let secret = [1u8; 32];
        let n1 = compute_nullifier(&secret, &[1u8; 32]);
        let n2 = compute_nullifier(&secret, &[2u8; 32]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_set_insert_and_detect() {
        let mut set = NullifierSet::new();
        let nullifier = [42u8; 32];

        assert!(set.insert(nullifier));  // first insert succeeds
        assert!(!set.insert(nullifier)); // second insert = double-spend
    }

    #[test]
    fn test_nullifier_set_contains() {
        let mut set = NullifierSet::new();
        let nullifier = [42u8; 32];

        assert!(!set.contains(&nullifier));
        set.insert(nullifier);
        assert!(set.contains(&nullifier));
    }

    #[test]
    fn test_nullifier_set_multiple() {
        let mut set = NullifierSet::new();
        for i in 0u8..10 {
            let mut n = [0u8; 32];
            n[0] = i;
            assert!(set.insert(n));
        }
        assert_eq!(set.len(), 10);
    }

    // ---- file-backed persistence tests ----

    /// Helper: create a unique temporary file path for testing.
    fn temp_nullifier_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "specter_nullifier_test_{}_{}.bin",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    /// Clean up a temp file (best-effort).
    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_file_backed_basic_insert_and_reload() {
        let path = temp_nullifier_path("basic");
        // Ensure no leftover from a previous run.
        cleanup(&path);

        // First session: insert two nullifiers.
        {
            let mut set = NullifierSet::with_file(&path).unwrap();
            assert!(set.is_empty());
            assert!(set.insert([1u8; 32]));
            assert!(set.insert([2u8; 32]));
            assert_eq!(set.len(), 2);
        }

        // Second session: reopen the same file -- nullifiers must survive.
        {
            let set = NullifierSet::with_file(&path).unwrap();
            assert_eq!(set.len(), 2);
            assert!(set.contains(&[1u8; 32]));
            assert!(set.contains(&[2u8; 32]));
            assert!(!set.contains(&[3u8; 32]));
        }

        cleanup(&path);
    }

    #[test]
    fn test_file_backed_double_spend_across_restarts() {
        let path = temp_nullifier_path("double_spend");
        cleanup(&path);

        // Session 1: insert a nullifier.
        {
            let mut set = NullifierSet::with_file(&path).unwrap();
            assert!(set.insert([42u8; 32]));
        }

        // Session 2: the same nullifier must be rejected.
        {
            let mut set = NullifierSet::with_file(&path).unwrap();
            assert!(!set.insert([42u8; 32]), "double-spend should be detected across restarts");
        }

        cleanup(&path);
    }

    #[test]
    fn test_file_backed_file_size_validation() {
        let path = temp_nullifier_path("bad_size");
        cleanup(&path);

        // Write 33 bytes (not a multiple of 32).
        std::fs::write(&path, [0u8; 33]).unwrap();

        let result = NullifierSet::with_file(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        cleanup(&path);
    }

    #[test]
    fn test_file_backed_empty_file() {
        let path = temp_nullifier_path("empty");
        cleanup(&path);

        // Create an empty file first.
        std::fs::write(&path, []).unwrap();

        let set = NullifierSet::with_file(&path).unwrap();
        assert!(set.is_empty());

        cleanup(&path);
    }

    #[test]
    fn test_file_backed_creates_new_file() {
        let path = temp_nullifier_path("create_new");
        cleanup(&path);

        assert!(!path.exists());
        let set = NullifierSet::with_file(&path).unwrap();
        assert!(set.is_empty());
        assert!(path.exists());

        cleanup(&path);
    }

    // ---- ConcurrentNullifierSet tests ----

    #[test]
    fn test_concurrent_basic_insert() {
        let set = ConcurrentNullifierSet::empty();
        assert!(set.is_empty());
        assert!(set.insert([1u8; 32]));
        assert!(!set.insert([1u8; 32])); // double-spend
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[1u8; 32]));
    }

    #[test]
    fn test_concurrent_parallel_inserts_of_same_nullifier() {
        use std::thread;

        let set = ConcurrentNullifierSet::empty();
        let nullifier = [0x42u8; 32];
        let thread_count = 32;

        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let s = set.clone();
                thread::spawn(move || s.insert(nullifier))
            })
            .collect();

        let successes: usize = handles
            .into_iter()
            .map(|h| h.join().unwrap() as usize)
            .sum();

        // Exactly one thread must see the "first-insert" path; the rest
        // must observe a double-spend. No matter the scheduling, never
        // more than one, never zero.
        assert_eq!(
            successes, 1,
            "exactly one concurrent insert of the same nullifier must succeed"
        );
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_concurrent_parallel_inserts_of_distinct_nullifiers() {
        use std::thread;

        let set = ConcurrentNullifierSet::empty();
        let thread_count = 16;
        let per_thread = 32;

        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                let s = set.clone();
                thread::spawn(move || {
                    let mut ok = 0;
                    for i in 0..per_thread {
                        let mut n = [0u8; 32];
                        n[0] = t as u8;
                        n[1] = i as u8;
                        if s.insert(n) {
                            ok += 1;
                        }
                    }
                    ok
                })
            })
            .collect();

        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, thread_count * per_thread);
        assert_eq!(set.len(), thread_count * per_thread);
    }

    #[test]
    fn test_file_backed_duplicate_within_session() {
        let path = temp_nullifier_path("dup_session");
        cleanup(&path);

        {
            let mut set = NullifierSet::with_file(&path).unwrap();
            assert!(set.insert([7u8; 32]));
            // Duplicate within the same session should not be written again.
            assert!(!set.insert([7u8; 32]));
        }

        // File should contain exactly one 32-byte entry.
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), 32);

        cleanup(&path);
    }
}
