use {
    futures::future::join_all,
    solana_sdk::{
        instruction::Instruction,
        signature::{Keypair, Signer},
        transaction::Transaction,
    },
    solana_test_validator::{TestValidator, TestValidatorGenesis},
    solana_zk_token_sdk::{
        encryption::pedersen::Pedersen, instruction::BatchedRangeProofU64Data,
        zk_token_proof_instruction::verify_batched_verify_range_proof_u64,
    },
    std::{sync::Arc, time::Instant},
};

#[tokio::main]
async fn main() {
    let (test_validator, payer) = new_validator_for_test().await;

    let payer: Arc<dyn Signer> = Arc::new(payer);
    let rpc_client = Arc::new(test_validator.get_async_rpc_client());
    let blockhash = rpc_client.get_latest_blockhash().await.unwrap();

    // Hard-coded three consecutive transaction execution
    let instructions = vec![batched_range_proof_u64()];
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[payer.clone()],
        rpc_client.get_latest_blockhash().await.unwrap(),
    );

    let first_tx_start = Instant::now();
    let first_result = rpc_client.send_and_confirm_transaction(&transaction).await;
    println!("first tx: {:?}", first_result);
    println!("first time: {:?}", first_tx_start.elapsed().as_millis());

    let instructions = vec![batched_range_proof_u64()];
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[payer.clone()],
        rpc_client.get_latest_blockhash().await.unwrap(),
    );

    let second_tx_start = Instant::now();
    let second_result = rpc_client.send_and_confirm_transaction(&transaction).await;
    println!("second tx: {:?}", second_result);
    println!("second time: {:?}", second_tx_start.elapsed().as_millis());

    let instructions = vec![batched_range_proof_u64()];
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[payer.clone()],
        rpc_client.get_latest_blockhash().await.unwrap(),
    );

    let third_tx_start = Instant::now();
    let third_result = rpc_client.send_and_confirm_transaction(&transaction).await;
    println!("third tx: {:?}", third_result);
    println!("third time: {:?}", third_tx_start.elapsed().as_millis());

    // Parallel transaction execution
    let mut txs = vec![];
    for _ in 0..100 {
        let instructions = vec![batched_range_proof_u64()];
        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&payer.pubkey()),
            &[payer.clone()],
            blockhash,
        );
        txs.push((rpc_client.clone(), transaction));
    }

    let futures = txs
        .into_iter()
        .map(|(rpc, tx)| async move {
            let result = rpc.send_and_confirm_transaction(&tx).await;
            println!("result: {:?}", result);
            result
        })
        .collect::<Vec<_>>();

    let result: Vec<_> = join_all(futures).await.into_iter().collect();
    println!("result: {:?}", result);
}

fn batched_range_proof_u64() -> Instruction {
    let amount_1 = 23_u64;
    let amount_2 = 24_u64;

    let (commitment_1, opening_1) = Pedersen::new(amount_1);
    let (commitment_2, opening_2) = Pedersen::new(amount_2);

    let proof_data = BatchedRangeProofU64Data::new(
        vec![&commitment_1, &commitment_2],
        vec![amount_1, amount_2],
        vec![32, 32],
        vec![&opening_1, &opening_2],
    )
    .unwrap();

    verify_batched_verify_range_proof_u64(None, &proof_data)
}

async fn new_validator_for_test() -> (TestValidator, Keypair) {
    solana_logger::setup();
    let test_validator_genesis = TestValidatorGenesis::default();
    test_validator_genesis.start_async().await
}
