//! Wallet — manages multiple Proof-Carrying Tokens.
//!
//! Provides balance tracking, token selection for spending, and
//! storage management.

use crate::token::ProofCarryingToken;

/// A wallet holding multiple Proof-Carrying Tokens.
pub struct Wallet {
    tokens: Vec<ProofCarryingToken>,
}

impl Wallet {
    /// Create an empty wallet.
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Add a token to the wallet.
    pub fn add_token(&mut self, token: ProofCarryingToken) {
        self.tokens.push(token);
    }

    /// Remove a token by its ID. Returns the removed token if found.
    pub fn remove_token(&mut self, token_id: &[u8; 32]) -> Option<ProofCarryingToken> {
        if let Some(pos) = self.tokens.iter().position(|t| &t.token_id == token_id) {
            Some(self.tokens.remove(pos))
        } else {
            None
        }
    }

    /// Total balance across all tokens.
    pub fn balance(&self) -> u64 {
        self.tokens.iter().map(|t| t.value).sum()
    }

    /// Number of tokens in the wallet.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Select the best token for spending a given amount.
    ///
    /// Strategy: smallest token that covers the amount and has
    /// remaining transfer capacity (not needing renewal).
    pub fn select_token(&self, amount: u64) -> Option<&ProofCarryingToken> {
        self.tokens
            .iter()
            .filter(|t| t.value >= amount && !t.needs_renewal())
            .min_by_key(|t| t.value)
    }

    /// Get all tokens that need renewal (exceeded transfer bound).
    pub fn tokens_needing_renewal(&self) -> Vec<&ProofCarryingToken> {
        self.tokens.iter().filter(|t| t.needs_renewal()).collect()
    }

    /// Get all tokens with their basic info.
    pub fn list_tokens(&self) -> Vec<TokenInfo> {
        self.tokens
            .iter()
            .map(|t| TokenInfo {
                token_id: t.token_id,
                value: t.value,
                transfer_count: t.transfer_count,
                recursion_bound: t.recursion_bound,
                needs_renewal: t.needs_renewal(),
                has_credential: t.has_credential(),
                has_bond: t.has_bond(),
                estimated_size: t.estimated_size(),
            })
            .collect()
    }

    /// Total estimated storage size of all tokens.
    pub fn total_storage_bytes(&self) -> usize {
        self.tokens.iter().map(|t| t.estimated_size()).sum()
    }

    /// Check if the wallet is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary info for a token in the wallet.
#[derive(Debug)]
pub struct TokenInfo {
    pub token_id: [u8; 32],
    pub value: u64,
    pub transfer_count: u32,
    pub recursion_bound: u32,
    pub needs_renewal: bool,
    pub has_credential: bool,
    pub has_bond: bool,
    pub estimated_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};
    use crate::transfer;

    fn setup_mint() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 5,
        })
    }

    #[test]
    fn test_empty_wallet() {
        let wallet = Wallet::new();
        assert!(wallet.is_empty());
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.token_count(), 0);
    }

    #[test]
    fn test_add_and_balance() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(200, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());

        assert_eq!(wallet.balance(), 800);
        assert_eq!(wallet.token_count(), 3);
    }

    #[test]
    fn test_select_token_smallest_fit() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(1000, &[1, 2], None).unwrap());

        // Should select 500 (smallest that covers 400)
        let selected = wallet.select_token(400).unwrap();
        assert_eq!(selected.value, 500);

        // Should select 100 (exact match)
        let selected = wallet.select_token(100).unwrap();
        assert_eq!(selected.value, 100);

        // No token covers 2000
        assert!(wallet.select_token(2000).is_none());
    }

    #[test]
    fn test_select_skips_renewal_needed() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        let token = mint.issue(100, &[1, 2], None).unwrap();
        // Transfer 5 times to reach bound
        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(&current).unwrap().token;
        }
        wallet.add_token(current); // needs renewal

        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());

        // Should select 500 (100 needs renewal)
        let selected = wallet.select_token(50).unwrap();
        assert_eq!(selected.value, 500);
    }

    #[test]
    fn test_remove_token() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        let token = mint.issue(100, &[1, 2], None).unwrap();
        let id = token.token_id;
        wallet.add_token(token);

        assert_eq!(wallet.token_count(), 1);
        let removed = wallet.remove_token(&id).unwrap();
        assert_eq!(removed.value, 100);
        assert!(wallet.is_empty());
    }

    #[test]
    fn test_tokens_needing_renewal() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        // Fresh token
        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());

        // Exhausted token
        let token = mint.issue(200, &[1, 2], None).unwrap();
        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(&current).unwrap().token;
        }
        wallet.add_token(current);

        let needing = wallet.tokens_needing_renewal();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].value, 200);
    }

    #[test]
    fn test_list_tokens() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(200, &[1, 2], None).unwrap());

        let list = wallet.list_tokens();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].value, 100);
        assert_eq!(list[1].value, 200);
    }

    #[test]
    fn test_total_storage() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(200, &[1, 2], None).unwrap());

        assert!(wallet.total_storage_bytes() > 0);
    }
}
