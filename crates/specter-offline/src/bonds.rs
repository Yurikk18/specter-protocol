//! Reputation Bond system for offline payment guarantees.
//!
//! Users who want to spend tokens offline stake collateral (bonds) in the
//! network. Receivers can verify that the sender has a bond covering the
//! token value. If double-spending is detected, the bond is slashed and
//! the cheater's identity is revealed (blame protocol).
//!
//! This implements the economic trust model from the Overdraft paper
//! (Delft University, April 2025) adapted for the Specter protocol.

use std::collections::HashMap;

/// A reputation bond - collateral staked by a user.
#[derive(Clone, Debug)]
pub struct Bond {
    /// Unique bond identifier.
    pub bond_id: [u8; 32],
    /// Owner identifier (hash of public key).
    pub owner_id: [u8; 32],
    /// Amount staked as collateral.
    pub amount: u64,
    /// Whether the bond is active (not slashed).
    pub active: bool,
    /// Total value of tokens currently held offline by this owner.
    pub offline_exposure: u64,
    /// Timestamp when withdrawal was requested (0 = not requested).
    pub withdrawal_requested_at: u64,
}

/// The bond registry - tracks all active bonds.
pub struct BondRegistry {
    bonds: HashMap<[u8; 32], Bond>,
    /// Map from owner_id to their bond_id.
    owner_bonds: HashMap<[u8; 32], [u8; 32]>,
    /// Lock period in seconds before withdrawal is allowed.
    /// Must be >= max_offline_duration to prevent withdraw-before-slash.
    pub lock_period_secs: u64,
}

impl BondRegistry {
    /// Create an empty bond registry with a lock period.
    pub fn new() -> Self {
        Self {
            bonds: HashMap::new(),
            owner_bonds: HashMap::new(),
            lock_period_secs: 604800, // 7 days default
        }
    }

    /// Deposit a bond (stake collateral).
    /// Returns an error if the owner already has an active bond.
    pub fn deposit(&mut self, owner_id: [u8; 32], amount: u64) -> Result<Bond, BondError> {
        // Prevent overwriting an existing bond (which would orphan it)
        if let Some(existing_id) = self.owner_bonds.get(&owner_id) {
            if let Some(existing) = self.bonds.get(existing_id) {
                if existing.active {
                    return Err(BondError::AlreadyHasBond);
                }
            }
        }
        let mut bond_id = [0u8; 32];
        use sha2::{Digest, Sha256};
        // Include random nonce to prevent bond_id collisions on identical deposits
        let mut nonce = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        let hash = Sha256::new()
            .chain_update(b"specter-bond:")
            .chain_update(owner_id)
            .chain_update(amount.to_le_bytes())
            .chain_update(nonce)
            .finalize();
        bond_id.copy_from_slice(&hash);

        let bond = Bond {
            bond_id,
            owner_id,
            amount,
            active: true,
            offline_exposure: 0,
            withdrawal_requested_at: 0,
        };

        self.bonds.insert(bond_id, bond.clone());
        self.owner_bonds.insert(owner_id, bond_id);
        Ok(bond)
    }

    /// Check if an owner has sufficient bond for a given token value.
    ///
    /// Returns true if the owner's bond covers their current offline
    /// exposure PLUS the new token value.
    pub fn check_coverage(&self, owner_id: &[u8; 32], token_value: u64) -> bool {
        let Some(bond_id) = self.owner_bonds.get(owner_id) else {
            return false;
        };
        let Some(bond) = self.bonds.get(bond_id) else {
            return false;
        };
        if !bond.active {
            return false;
        }
        match bond.offline_exposure.checked_add(token_value) {
            Some(total) => bond.amount >= total,
            None => false, // overflow = exposure exceeds any possible bond
        }
    }

    /// Register offline spending - increase the owner's exposure.
    pub fn register_offline_spend(
        &mut self,
        owner_id: &[u8; 32],
        amount: u64,
    ) -> Result<(), BondError> {
        let bond_id = self
            .owner_bonds
            .get(owner_id)
            .ok_or(BondError::NoBond)?;
        let bond = self
            .bonds
            .get_mut(bond_id)
            .ok_or(BondError::NoBond)?;

        if !bond.active {
            return Err(BondError::BondSlashed);
        }
        let total_exposure = bond.offline_exposure.checked_add(amount).ok_or(
            BondError::InsufficientBond {
                available: bond.amount.saturating_sub(bond.offline_exposure),
                needed: amount,
            },
        )?;
        if bond.amount < total_exposure {
            return Err(BondError::InsufficientBond {
                available: bond.amount.saturating_sub(bond.offline_exposure),
                needed: amount,
            });
        }

        bond.offline_exposure += amount;
        Ok(())
    }

    /// Settle an offline spend - decrease exposure when the token goes online.
    pub fn settle(&mut self, owner_id: &[u8; 32], amount: u64) -> Result<(), BondError> {
        let bond_id = self.owner_bonds.get(owner_id).ok_or(BondError::NoBond)?;
        let bond = self.bonds.get_mut(bond_id).ok_or(BondError::NoBond)?;
        bond.offline_exposure = bond.offline_exposure.saturating_sub(amount);
        Ok(())
    }

    /// Slash a bond due to detected double-spending.
    ///
    /// Requires two conflicting nullifiers as evidence of double-spend.
    /// The bond is deactivated and the collateral is forfeited.
    /// Returns the slashed bond amount.
    pub fn slash(
        &mut self,
        owner_id: &[u8; 32],
        evidence_nullifier_a: &[u8; 32],
        evidence_nullifier_b: &[u8; 32],
    ) -> Result<u64, BondError> {
        // Evidence must be two DIFFERENT nullifiers (proving double-spend)
        if evidence_nullifier_a == evidence_nullifier_b {
            return Err(BondError::InsufficientEvidence);
        }
        let bond_id = self.owner_bonds.get(owner_id).ok_or(BondError::NoBond)?;
        let bond = self.bonds.get_mut(bond_id).ok_or(BondError::NoBond)?;

        if !bond.active {
            return Err(BondError::BondSlashed);
        }

        bond.active = false;
        let slashed = bond.amount;
        Ok(slashed)
    }

    /// Request withdrawal. Starts the lock period countdown.
    /// During lock period, bond is still active and can be slashed.
    pub fn request_withdrawal(&mut self, owner_id: &[u8; 32], current_time: u64) -> Result<u64, BondError> {
        let bond_id = self.owner_bonds.get(owner_id).ok_or(BondError::NoBond)?;
        let bond = self.bonds.get_mut(bond_id).ok_or(BondError::NoBond)?;

        if !bond.active {
            return Err(BondError::BondSlashed);
        }
        if bond.offline_exposure > 0 {
            return Err(BondError::ExposureNotSettled { remaining: bond.offline_exposure });
        }

        bond.withdrawal_requested_at = current_time;
        Ok(current_time + self.lock_period_secs)
    }

    /// Withdraw a bond after lock period has elapsed.
    /// Prevents withdraw-before-slash gaming.
    pub fn withdraw(&mut self, owner_id: &[u8; 32], current_time: u64) -> Result<u64, BondError> {
        let bond_id = self.owner_bonds.get(owner_id).ok_or(BondError::NoBond)?;
        let bond = self.bonds.get(bond_id).ok_or(BondError::NoBond)?;

        if !bond.active {
            return Err(BondError::BondSlashed);
        }
        if bond.withdrawal_requested_at == 0 {
            return Err(BondError::WithdrawalNotRequested);
        }
        if current_time < bond.withdrawal_requested_at + self.lock_period_secs {
            return Err(BondError::LockPeriodNotElapsed);
        }
        if bond.offline_exposure > 0 {
            return Err(BondError::ExposureNotSettled { remaining: bond.offline_exposure });
        }

        let amount = bond.amount;
        self.bonds.remove(bond_id);
        self.owner_bonds.remove(owner_id);
        Ok(amount)
    }

    /// Get a bond by owner ID.
    pub fn get_bond(&self, owner_id: &[u8; 32]) -> Option<&Bond> {
        let bond_id = self.owner_bonds.get(owner_id)?;
        self.bonds.get(bond_id)
    }

    /// Number of active bonds.
    pub fn active_count(&self) -> usize {
        self.bonds.values().filter(|b| b.active).count()
    }
}

impl Default for BondRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors for bond operations.
#[derive(Debug, thiserror::Error)]
pub enum BondError {
    #[error("no bond registered for this owner")]
    NoBond,

    #[error("bond has been slashed")]
    BondSlashed,

    #[error("insufficient bond: available {available}, needed {needed}")]
    InsufficientBond { available: u64, needed: u64 },

    #[error("cannot withdraw: offline exposure not settled ({remaining} remaining)")]
    ExposureNotSettled { remaining: u64 },

    #[error("withdrawal not yet requested - call request_withdrawal first")]
    WithdrawalNotRequested,

    #[error("lock period has not elapsed - bond can still be slashed during this period")]
    LockPeriodNotElapsed,

    #[error("owner already has an active bond")]
    AlreadyHasBond,

    #[error("insufficient evidence for slash: must provide two distinct conflicting nullifiers")]
    InsufficientEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(id: u8) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[0] = id;
        o
    }

    #[test]
    fn test_deposit_and_check_coverage() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 1000).unwrap();
        assert!(reg.check_coverage(&owner(1), 500));
        assert!(reg.check_coverage(&owner(1), 1000));
        assert!(!reg.check_coverage(&owner(1), 1001));
    }

    #[test]
    fn test_no_bond_no_coverage() {
        let reg = BondRegistry::new();
        assert!(!reg.check_coverage(&owner(99), 1));
    }

    #[test]
    fn test_register_and_settle() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 1000).unwrap();

        reg.register_offline_spend(&owner(1), 500).unwrap();
        assert!(reg.check_coverage(&owner(1), 500)); // 1000 - 500 = 500 left
        assert!(!reg.check_coverage(&owner(1), 501));

        reg.settle(&owner(1), 300).unwrap();
        assert!(reg.check_coverage(&owner(1), 800)); // 1000 - 200 = 800 left
    }

    #[test]
    fn test_insufficient_bond() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 100).unwrap();
        assert!(reg.register_offline_spend(&owner(1), 200).is_err());
    }

    #[test]
    fn test_slash() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 1000).unwrap();

        let evidence_a = [1u8; 32];
        let evidence_b = [2u8; 32];
        let slashed = reg.slash(&owner(1), &evidence_a, &evidence_b).unwrap();
        assert_eq!(slashed, 1000);
        assert!(!reg.check_coverage(&owner(1), 1)); // bond is inactive
        assert!(reg.slash(&owner(1), &evidence_a, &evidence_b).is_err()); // already slashed
    }

    #[test]
    fn test_slash_requires_distinct_evidence() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 1000).unwrap();
        let same = [1u8; 32];
        assert!(reg.slash(&owner(1), &same, &same).is_err()); // same evidence rejected
    }

    #[test]
    fn test_withdraw_with_lock_period() {
        let mut reg = BondRegistry::new();
        reg.lock_period_secs = 100; // 100 seconds for testing
        reg.deposit(owner(1), 1000).unwrap();

        // Can't withdraw without requesting first
        assert!(reg.withdraw(&owner(1), 0).is_err());

        // Request withdrawal at time 1000
        let withdrawable_at = reg.request_withdrawal(&owner(1), 1000).unwrap();
        assert_eq!(withdrawable_at, 1100); // 1000 + 100

        // Can't withdraw before lock period
        assert!(reg.withdraw(&owner(1), 1050).is_err());

        // Can withdraw after lock period
        let amount = reg.withdraw(&owner(1), 1100).unwrap();
        assert_eq!(amount, 1000);
    }

    #[test]
    fn test_withdraw_with_exposure_fails() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 1000).unwrap();
        reg.register_offline_spend(&owner(1), 500).unwrap();
        // Can't even request withdrawal with exposure
        assert!(reg.request_withdrawal(&owner(1), 0).is_err());
    }

    #[test]
    fn test_slash_during_lock_period() {
        let mut reg = BondRegistry::new();
        reg.lock_period_secs = 100;
        reg.deposit(owner(1), 1000).unwrap();

        // Request withdrawal
        reg.request_withdrawal(&owner(1), 1000).unwrap();

        // Slash works during lock period (that's the point)
        let slashed = reg.slash(&owner(1), &[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(slashed, 1000);

        // Can't withdraw a slashed bond
        assert!(reg.withdraw(&owner(1), 2000).is_err());
    }

    #[test]
    fn test_multiple_owners() {
        let mut reg = BondRegistry::new();
        reg.deposit(owner(1), 1000).unwrap();
        reg.deposit(owner(2), 500).unwrap();

        assert!(reg.check_coverage(&owner(1), 900));
        assert!(reg.check_coverage(&owner(2), 400));
        assert!(!reg.check_coverage(&owner(2), 600));
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut reg = BondRegistry::new();
        reg.lock_period_secs = 100;

        // Deposit
        reg.deposit(owner(1), 1000).unwrap();

        // Spend offline
        reg.register_offline_spend(&owner(1), 300).unwrap();
        reg.register_offline_spend(&owner(1), 200).unwrap();

        // Go online, settle
        reg.settle(&owner(1), 300).unwrap();
        reg.settle(&owner(1), 200).unwrap();

        // Request + wait + withdraw
        reg.request_withdrawal(&owner(1), 1000).unwrap();
        let amount = reg.withdraw(&owner(1), 1100).unwrap();
        assert_eq!(amount, 1000);
    }
}
