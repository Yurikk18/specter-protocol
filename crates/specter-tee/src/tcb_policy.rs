//! TCB (Trusted Computing Base) policy for SEV-SNP attestation
//! verification. Encodes deployment-specific requirements for the
//! minimum firmware version, allowed launch measurements, and
//! maximum VMPL level.

use subtle::ConstantTimeEq;

/// A 48-byte SHA-384 launch measurement digest.
pub type LaunchMeasurement = [u8; 48];

/// Minimum TCB component versions. Each field corresponds to one
/// component in the AMD SEV-SNP `TcbVersion` struct. All fields
/// default to 0 (accept any version).
#[derive(Clone, Debug, Default)]
pub struct TcbFloor {
    /// Minimum bootloader SVN.
    pub bootloader: u8,
    /// Minimum TEE (PSP OS) SVN.
    pub tee: u8,
    /// Minimum SNP firmware SVN.
    pub snp: u8,
    /// Minimum microcode patch level.
    pub microcode: u8,
}

/// Policy for TCB version enforcement and measurement pinning.
#[derive(Clone, Debug)]
pub struct TcbPolicy {
    /// Component-wise minimum TCB version floor.
    pub min_tcb: TcbFloor,

    /// Allowed launch measurement digests (SHA-384). An empty list
    /// means "any measurement is accepted" — use **only** in dev.
    pub allowed_measurements: Vec<LaunchMeasurement>,

    /// Maximum VMPL level (0–3). VMPL 0 is the most privileged
    /// guest context. Set to 0 for production mints.
    pub max_vmpl: u32,
}

impl TcbPolicy {
    /// Permissive "development" policy. **NEVER use in production.**
    pub fn permissive() -> Self {
        Self {
            min_tcb: TcbFloor::default(),
            allowed_measurements: Vec::new(),
            max_vmpl: 3,
        }
    }

    /// Validate a report's TCB fields against this policy.
    ///
    /// `(bootloader, tee, snp, microcode)` are the four component
    /// versions from the SNP report's `current_tcb` field.
    pub fn check(
        &self,
        bootloader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
        report_measurement: &[u8; 48],
        report_vmpl: u32,
    ) -> Result<(), TcbPolicyViolation> {
        // Component-wise TCB floor check.
        if bootloader < self.min_tcb.bootloader
            || tee < self.min_tcb.tee
            || snp < self.min_tcb.snp
            || microcode < self.min_tcb.microcode
        {
            return Err(TcbPolicyViolation::TcbTooOld {
                report: format!("bl={bootloader} tee={tee} snp={snp} uc={microcode}"),
                minimum: format!(
                    "bl={} tee={} snp={} uc={}",
                    self.min_tcb.bootloader,
                    self.min_tcb.tee,
                    self.min_tcb.snp,
                    self.min_tcb.microcode,
                ),
            });
        }
        // VMPL check.
        if report_vmpl > self.max_vmpl {
            return Err(TcbPolicyViolation::VmplTooHigh {
                report: report_vmpl,
                maximum: self.max_vmpl,
            });
        }
        // Measurement check (skip if allow-list is empty).
        if !self.allowed_measurements.is_empty() {
            let found = self.allowed_measurements.iter().any(|m| {
                bool::from(m.as_slice().ct_eq(report_measurement.as_slice()))
            });
            if !found {
                return Err(TcbPolicyViolation::MeasurementNotAllowed);
            }
        }
        Ok(())
    }
}

/// TCB policy violation error.
#[derive(Debug, thiserror::Error)]
pub enum TcbPolicyViolation {
    /// Report firmware is older than the policy floor.
    #[error("report TCB ({report}) below minimum ({minimum})")]
    TcbTooOld {
        /// TCB components from the report.
        report: String,
        /// Minimum components required.
        minimum: String,
    },
    /// Report was issued at a higher VMPL than allowed.
    #[error("report VMPL {report} exceeds maximum {maximum}")]
    VmplTooHigh {
        /// VMPL from the report.
        report: u32,
        /// Maximum allowed by policy.
        maximum: u32,
    },
    /// Launch measurement is not in the allowed set.
    #[error("launch measurement not in allowed set")]
    MeasurementNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_accepts_anything() {
        let p = TcbPolicy::permissive();
        p.check(0, 0, 0, 0, &[0u8; 48], 3).unwrap();
        p.check(255, 255, 255, 255, &[0xFF; 48], 0).unwrap();
    }

    #[test]
    fn rejects_old_tcb_bootloader() {
        let p = TcbPolicy {
            min_tcb: TcbFloor {
                bootloader: 5,
                ..Default::default()
            },
            allowed_measurements: vec![],
            max_vmpl: 3,
        };
        let res = p.check(4, 0, 0, 0, &[0; 48], 0);
        assert!(matches!(res, Err(TcbPolicyViolation::TcbTooOld { .. })));
        p.check(5, 0, 0, 0, &[0; 48], 0).unwrap();
    }

    #[test]
    fn rejects_old_tcb_microcode() {
        let p = TcbPolicy {
            min_tcb: TcbFloor {
                microcode: 10,
                ..Default::default()
            },
            allowed_measurements: vec![],
            max_vmpl: 3,
        };
        let res = p.check(0, 0, 0, 9, &[0; 48], 0);
        assert!(matches!(res, Err(TcbPolicyViolation::TcbTooOld { .. })));
        p.check(0, 0, 0, 10, &[0; 48], 0).unwrap();
    }

    #[test]
    fn rejects_high_vmpl() {
        let p = TcbPolicy {
            min_tcb: TcbFloor::default(),
            allowed_measurements: vec![],
            max_vmpl: 0,
        };
        let res = p.check(0, 0, 0, 0, &[0; 48], 1);
        assert!(matches!(res, Err(TcbPolicyViolation::VmplTooHigh { .. })));
    }

    #[test]
    fn rejects_unknown_measurement() {
        let mut allowed = [0u8; 48];
        allowed[0] = 0xAA;
        let p = TcbPolicy {
            min_tcb: TcbFloor::default(),
            allowed_measurements: vec![allowed],
            max_vmpl: 3,
        };
        let res = p.check(0, 0, 0, 0, &[0xBB; 48], 0);
        assert!(matches!(res, Err(TcbPolicyViolation::MeasurementNotAllowed)));
    }

    #[test]
    fn accepts_known_measurement() {
        let mut m = [0u8; 48];
        m[0] = 0xAA;
        let p = TcbPolicy {
            min_tcb: TcbFloor::default(),
            allowed_measurements: vec![m],
            max_vmpl: 3,
        };
        p.check(0, 0, 0, 0, &m, 0).unwrap();
    }

    #[test]
    fn empty_measurement_list_accepts_all() {
        let p = TcbPolicy {
            min_tcb: TcbFloor::default(),
            allowed_measurements: vec![],
            max_vmpl: 3,
        };
        p.check(0, 0, 0, 0, &[0xFF; 48], 0).unwrap();
    }
}
