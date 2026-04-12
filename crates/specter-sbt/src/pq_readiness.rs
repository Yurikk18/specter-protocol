//! Post-quantum readiness detection for the SBT scheme.
//!
//! The `pq-voleith` feature flag is reserved for a future
//! construction that replaces the Schnorr NIZK with VOLE-in-the-head
//! and the DH-OPRF with a lattice-based OPRF (Leap, Eurocrypt 2025).
//! Neither primitive has a production-quality Rust implementation as
//! of 2026-04.
//!
//! This module provides:
//! 1. A **compile-time gate** that refuses to build if `pq-voleith`
//!    is enabled prematurely.
//! 2. A **runtime detection** struct ([`PqReadiness`]) that callers
//!    can query at startup to determine whether PQ primitives are
//!    available and to log the system's security posture.
//!
//! # Upgrade path
//!
//! When a production-quality VOLEitH + lattice-OPRF crate appears:
//!
//! 1. Remove the `compile_error!` below.
//! 2. Add the new crate to `[dependencies]` behind `pq-voleith`.
//! 3. Implement a second `BlindSignatureScheme` that wraps the new
//!    primitives (the trait surface is stable and was designed for
//!    this swap).
//! 4. Update [`PqReadiness::detect`] to return `true` when the
//!    feature is enabled and the linked crate passes a self-test.

// ── Compile-time gate ────────────────────────────────────────────
#[cfg(feature = "pq-voleith")]
compile_error!(
    "The `pq-voleith` feature is reserved for a future VOLEitH + \
     lattice-OPRF construction. No production-quality Rust crate \
     for generic VOLEitH ZK or the Leap OPRF exists yet (as of \
     2026-04). Remove this feature flag until specter-sbt gains a \
     concrete implementation."
);

/// Which PQ primitive components are available at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqReadiness {
    /// True if a generic VOLEitH ZK prover/verifier is linked.
    pub voleith_available: bool,
    /// True if a lattice-based OPRF (Leap or Pool) is linked.
    pub lattice_oprf_available: bool,
}

impl PqReadiness {
    /// Probe the runtime environment for PQ primitive availability.
    ///
    /// In the current release both fields are always `false`. When a
    /// concrete implementation is linked, this function will detect
    /// it via feature flags.
    pub fn detect() -> Self {
        Self {
            voleith_available: false,
            lattice_oprf_available: false,
        }
    }

    /// Returns `true` if ALL PQ primitives needed for the full
    /// VOLEitH + lattice-OPRF SBT construction are available.
    pub fn is_fully_pq_ready(&self) -> bool {
        self.voleith_available && self.lattice_oprf_available
    }

    /// Human-readable summary for startup logging.
    pub fn summary(&self) -> String {
        if self.is_fully_pq_ready() {
            "PQ-SBT: all primitives available — using lattice-OPRF + VOLEitH".to_string()
        } else {
            format!(
                "PQ-SBT: NOT READY (VOLEitH={}, lattice-OPRF={}). \
                 Using classical DH-OPRF + Schnorr NIZK.",
                self.voleith_available, self.lattice_oprf_available
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_not_ready() {
        let r = PqReadiness::detect();
        assert!(!r.voleith_available);
        assert!(!r.lattice_oprf_available);
        assert!(!r.is_fully_pq_ready());
    }

    #[test]
    fn summary_mentions_classical() {
        let r = PqReadiness::detect();
        let s = r.summary();
        assert!(s.contains("NOT READY"));
        assert!(s.contains("classical"));
    }

    #[test]
    fn fully_ready_when_both_true() {
        let r = PqReadiness {
            voleith_available: true,
            lattice_oprf_available: true,
        };
        assert!(r.is_fully_pq_ready());
        assert!(r.summary().contains("all primitives available"));
    }

    #[test]
    fn not_ready_when_partial() {
        let r = PqReadiness {
            voleith_available: true,
            lattice_oprf_available: false,
        };
        assert!(!r.is_fully_pq_ready());
    }
}
