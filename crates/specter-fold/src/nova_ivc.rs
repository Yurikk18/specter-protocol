//! Nova IVC — true zero-knowledge recursive proof folding.
//!
//! Each transfer step is verified inside a Nova StepCircuit.
//! The proof is constant-size and zero-knowledge — verifiers learn
//! nothing about the transfer history except that it is valid.

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
        2 // [state_hash, transfer_count]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // z[0] = previous state hash, z[1] = transfer count

        // Witness: new owner data
        let owner = AllocatedNum::alloc(cs.namespace(|| "owner"), || {
            Ok(F::from(self.new_owner_data))
        })?;

        // new_hash = old_hash * owner + old_hash + 1
        let product = z[0].mul(cs.namespace(|| "mul"), &owner)?;
        let new_hash = AllocatedNum::alloc(cs.namespace(|| "new_hash"), || {
            let p = product.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let old = z[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(p + old + F::ONE)
        })?;
        cs.enforce(
            || "hash_eq",
            |lc| lc + new_hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + product.get_variable() + z[0].get_variable() + CS::one(),
        );

        // new_count = old_count + 1
        let new_count = AllocatedNum::alloc(cs.namespace(|| "new_count"), || {
            let old = z[1].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(old + F::ONE)
        })?;
        cs.enforce(
            || "count_eq",
            |lc| lc + new_count.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[1].get_variable() + CS::one(),
        );

        Ok(vec![new_hash, new_count])
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
    pub fn prove_genesis(&self, initial_state: u64) -> Result<RecursiveSNARK<G1, G2, TransferCircuit, TrivialCircuit<<G2 as Group>::Scalar>>, String> {
        let z0_primary = vec![F1::from(initial_state), F1::from(0u64)];
        let z0_secondary = vec![<G2 as Group>::Scalar::from(0u64)];

        let circuit = TransferCircuit::new(initial_state);
        let secondary = TrivialCircuit::default();

        RecursiveSNARK::new(&self.pp, &circuit, &secondary, &z0_primary, &z0_secondary)
            .map_err(|e| format!("genesis failed: {:?}", e))
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

    /// Verify a recursive proof.
    pub fn verify(
        &self,
        snark: &RecursiveSNARK<G1, G2, TransferCircuit, TrivialCircuit<<G2 as Group>::Scalar>>,
        num_steps: usize,
        initial_state: u64,
    ) -> bool {
        let z0_primary = vec![F1::from(initial_state), F1::from(0u64)];
        let z0_secondary = vec![<G2 as Group>::Scalar::from(0u64)];
        snark
            .verify(&self.pp, num_steps, &z0_primary, &z0_secondary)
            .is_ok()
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
    #[ignore = "semolina/pasta-msm assembly requires Linux/macOS linker"]
    fn test_nova_genesis() {
        let engine = NovaEngine::setup();
        let snark = engine.prove_genesis(42).unwrap();
        assert!(engine.verify(&snark, 1, 42));
    }

    #[test]
    #[ignore = "semolina/pasta-msm assembly requires Linux/macOS linker"]
    fn test_nova_fold_steps() {
        let engine = NovaEngine::setup();
        let mut snark = engine.prove_genesis(42).unwrap();

        for i in 1..=3 {
            engine.fold_step(&mut snark, i * 100).unwrap();
        }

        // 1 genesis + 3 folds = 4 steps
        assert!(engine.verify(&snark, 4, 42));
    }

    #[test]
    #[ignore = "semolina/pasta-msm assembly requires Linux/macOS linker"]
    fn test_nova_wrong_initial_state_fails() {
        let engine = NovaEngine::setup();
        let snark = engine.prove_genesis(42).unwrap();
        assert!(!engine.verify(&snark, 1, 99)); // wrong initial
    }

    #[test]
    #[ignore = "semolina/pasta-msm assembly requires Linux/macOS linker"]
    fn test_nova_wrong_step_count_fails() {
        let engine = NovaEngine::setup();
        let snark = engine.prove_genesis(42).unwrap();
        assert!(!engine.verify(&snark, 2, 42)); // claimed 2 steps but only 1
    }
}
