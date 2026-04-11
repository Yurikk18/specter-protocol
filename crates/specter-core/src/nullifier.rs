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

#[cfg(test)]
mod tests {
    use super::*;

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
        std::fs::write(&path, &[0u8; 33]).unwrap();

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
        std::fs::write(&path, &[]).unwrap();

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
