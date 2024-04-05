//! The native Range Proof program.
//!
//! The program verifies that a committed value in a Pedersen commitment is in a certain range.

pub mod instruction;

// Program Id of the Range Proof program
solana_program::declare_id!("RangeProof111111111111111111111111111111111");
