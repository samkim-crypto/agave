//! The native ZK ElGamal proof program.
//!
//! The program verifies a number of zero-knowledge proofs that are tailored to work with Pedersen
//! commitments and ElGamal encryption over the elliptic curve curve25519. A general overview of
//! the program as well as the technical details of some of the proof instructions can be found in
//! the [`ZK ElGamal proof`] documentation.
//!
//! [`ZK ElGamal proof`]: https://docs.solanalabs.com/runtime/zk-token-proof

pub mod instruction;

// Program Id of the ZK ElGamal Proof program
solana_program::declare_id!("ZkTokenProof1111111111111111111111111111111");
