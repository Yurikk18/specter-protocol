//! Nova IVC - recursive proof folding over Pallas/Vesta curves.
//!
//! Each transfer step is verified inside a Nova StepCircuit.
//! The proof is constant-size and provides recursive verification.
//!
//! # Current Limitation
//!
//! The `TransferCircuit` currently constrains only a step counter.
//! It does NOT embed Ristretto255 operations (Schnorr verification,
//! Pedersen commitment checks) because those require a different
//! curve than Pallas/Vesta. Adding cross-curve verification inside
//! R1CS constraints requires non-native field arithmetic (expensive).
//!
//! The step counter proves "N sequential prove_step calls occurred."
//! Actual transfer validity relies on the Schnorr accumulator
//! (accumulator.rs), the mint blind signature, and the nullifier set.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::{
    traits::{circuit::StepCircuit, circuit::TrivialCircuit, Group},
    PublicParams, RecursiveSNARK,
};
use pasta_curves::{pallas, vesta};

/// Curve groups for Nova.
pub type G1 = pallas::Point;
pub type G2 = vesta::Point;
pub type F1 = <G1 as Group>::Scalar;

/// The transfer verification circuit.
///
/// Each step takes [state_hash, transfer_count] and produces
/// an updated [new_state_hash, transfer_count + 1].
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    /// New owner data to fold in (private witness).
    new_owner_data: u64,
}

impl TransferCircuit {
    pub fn new(data: u64) -> Self {
        Self { new_owner_data: data }
    }
    pub fn blank() -> Self {
        Self { new_owner_data: 0 }
    }
}

impl<F: ff::PrimeField> StepCircuit<F> for TransferCircuit {
    fn arity(&self) -> usize {
        1 // [transfer_count]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // z[0] = transfer count
        // Each step increments by 1

        let new_count = AllocatedNum::alloc(cs.namespace(|| "new_count"), || {
            let old = z[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(old + F::ONE)
        })?;

        cs.enforce(
            || "count_increment",
            |lc| lc + new_count.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[0].get_variable() + CS::one(),
        );

        Ok(vec![new_count])
    }
}

/// Nova IVC engine for Specter.
pub struct NovaEngine {
    pp: PublicParams<G1, G2, TransferCircuit, TrivialCircuit<<G2 as Group>::Scalar>>,
}

impl NovaEngine {
    /// One-time setup (generates public parameters).
    pub fn setup() -> Self {
        let c_primary = TransferCircuit::blank();
        let c_secondary = TrivialCircuit::default();
        let pp = PublicParams::setup(&c_primary, &c_secondary);
        Self { pp }
    }

    /// Create the genesis proof (step 0).
    pub fn prove_genesis(&self, initial_count: u64) -> Result<RecursiveSNARK<G1, G2, TransferCircuit, TrivialCircuit<<G2 as Group>::Scalar>>, String> {
        let z0_primary = [F1::from(initial_count)];
        let z0_secondary = [<G2 as Group>::Scalar::from(0u64)];

        let circuit = TransferCircuit::new(0);
        let secondary = TrivialCircuit::default();

        let mut snark = RecursiveSNARK::new(&self.pp, &circuit, &secondary, &z0_primary, &z0_secondary)
            .map_err(|e| format!("genesis failed: {:?}", e))?;

        // Execute the first step (new creates the SNARK but doesn't execute step 0)
        snark.prove_step(&self.pp, &circuit, &secondary)
            .map_err(|e| format!("genesis step failed: {:?}", e))?;

        Ok(snark)
    }

    /// Fold a transfer step into the proof.
    pub fn fold_step(
        &self,
        snark: &mut RecursiveSNARK<G1, G2, TransferCircuit, TrivialCircuit<<G2 as Group>::Scalar>>,
        new_owner_data: u64,
    ) -> Result<(), String> {
        let circuit = TransferCircuit::new(new_owner_data);
        let secondary = TrivialCircuit::default();
        snark
            .prove_step(&self.pp, &circuit, &secondary)
            .map_err(|e| format!("fold failed: {:?}", e))
    }

    /// Verify a recursive proof. Returns Ok with the final outputs if valid.
    pub fn verify(
        &self,
        snark: &RecursiveSNARK<G1, G2, TransferCircuit, TrivialCircuit<<G2 as Group>::Scalar>>,
        num_steps: usize,
        initial_state: u64,
    ) -> bool {
        let z0_primary = [F1::from(initial_state)];
        let z0_secondary = [<G2 as Group>::Scalar::from(0u64)];
        match snark.verify(&self.pp, num_steps, &z0_primary, &z0_secondary) {
            Ok(_outputs) => true,
            Err(_e) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Nova IVC tests require Linux/macOS due to semolina/pasta-msm
    // assembly incompatibility with Windows linkers. The code compiles as a
    // library but the test executable cannot link pasta_to on Windows.
    // Run these tests on Linux: cargo test -p specter-fold -- nova

    #[test]
    #[ignore = "requires Linux/macOS (pasta-msm assembly)"]
    fn test_nova_genesis() {
        let engine = NovaEngine::setup();
        // Start counter at 0
        let snark = engine.prove_genesis(0).unwrap();
        // After 1 step, counter should be 1. Verify with initial z0=0.
        assert!(engine.verify(&snark, 1, 0));
    }

    #[test]
    #[ignore = "requires Linux/macOS (pasta-msm assembly)"]
    fn test_nova_fold_steps() {
        let engine = NovaEngine::setup();
        let mut snark = engine.prove_genesis(0).unwrap();

        for _ in 1..=3 {
            engine.fold_step(&mut snark, 0).unwrap();
        }

        // 1 genesis + 3 folds = 4 steps. Counter: 0 -> 1 -> 2 -> 3 -> 4
        assert!(engine.verify(&snark, 4, 0));
    }

    #[test]
    #[ignore = "requires Linux/macOS (pasta-msm assembly)"]
    fn test_nova_wrong_initial_state_fails() {
        let engine = NovaEngine::setup();
        let snark = engine.prove_genesis(0).unwrap();
        // Claim initial was 99 but it was 0
        assert!(!engine.verify(&snark, 1, 99));
    }

    #[test]
    #[ignore = "requires Linux/macOS (pasta-msm assembly)"]
    fn test_nova_wrong_step_count_fails() {
        let engine = NovaEngine::setup();
        let snark = engine.prove_genesis(0).unwrap();
        // Claim 2 steps but only did 1
        assert!(!engine.verify(&snark, 2, 0));
    }
}
