use crate::api_to_blockifier_conversion::starknet_rs_to_blockifier;
use crate::commitment_utils::{compute_class_commitment, format_commitment_facts};
use crate::context_builder::{build_block_context, chain_id_from_felt};
use crate::rpc_utils::{get_accessed_keys_with_block_hash, get_class_proofs, get_storage_proofs};
use crate::state_update::{get_formatted_state_update, get_subcalled_contracts_from_tx_traces};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::maybe_dummy_block_hash_and_number;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::Felt252;
use rpc_client::pathfinder::proofs::PathfinderProof;
use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::RpcClient;
use serde::Serialize;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet::core::types::{BlockId, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs};
use starknet::providers::Provider;
use starknet_api::block::{BlockHash, BlockNumber, StarknetVersion};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass;
use starknet_api::state::ContractClassComponentHashes;
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::{CommitmentInfo, OsBlockInput};
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_patricia::patricia_merkle_tree::types::SubTreeHeight;
use starknet_types_core::felt::Felt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generic function to serialize any serializable object and write it to a file
///
/// # Arguments
/// * `object` - Any object that implements the Serialize trait
/// * `file_path` - Path where the file should be written
/// * `format` - Optional format specification ("json", "yaml", etc.). Defaults to JSON.
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) on success, error on failure
///
/// # Examples
/// ```
/// let data = vec![1, 2, 3, 4, 5];
/// write_serializable_to_file(&data, "output/numbers.json", Some("json"))?;
///
/// let traces = get_transaction_traces();
/// write_serializable_to_file(&traces, "debug/traces.json", None)?;
/// ```
#[allow(dead_code)]
pub fn write_serializable_to_file<T>(
    object: &T,
    file_path: &str,
    format: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Serialize,
{
    // Create directory if it doesn't exist
    if let Some(parent) = Path::new(file_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(file_path)?;

    match format.unwrap_or("json") {
        "json" => {
            let json_string = serde_json::to_string_pretty(object)?;
            file.write_all(json_string.as_bytes())?;
        }
        "json-compact" => {
            let json_string = serde_json::to_string(object)?;
            file.write_all(json_string.as_bytes())?;
        }
        _ => {
            return Err(format!("Unsupported format: {}", format.unwrap_or("json")).into());
        }
    }

    file.flush()?;
    log::debug!("Successfully wrote serialized data to: {}", file_path);
    Ok(())
}

pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
const STATEFUL_MAPPING_START: Felt = Felt::from_hex_unchecked("0x80"); // 128

/// Helper function to populate accessed_keys_by_address with special address 0x2
/// based on accessed addresses, classes, and current storage mapping.
///
/// According to the storage mapping rules:
/// - Storage keys that require at most 127 bits and addresses of system contracts (0x1 and 0x2)
///   are not mapped and continue to be referred to directly
/// - We ignore values < 128 and address 0x1
/// - Keys are added to address 0x2 from contracts, classes, and existing storage keys
fn populate_alias_contract_keys(
    accessed_addresses: &HashSet<ContractAddress>,
    accessed_classes: &HashSet<ClassHash>,
    accessed_keys_by_address: &mut HashMap<ContractAddress, HashSet<StorageKey>>,
) {
    // Special address 0x2 for alias contract
    let alias_contract_address =
        ContractAddress::try_from(Felt::TWO).expect("0x2 should be a valid contract address");

    let mut alias_keys = HashSet::new();

    // Process accessed contract addresses
    for contract_address in accessed_addresses {
        let address_felt: Felt = (*contract_address).into();

        // Skip address 0x1 (system contract)
        if address_felt == Felt::ONE || address_felt == Felt::TWO {
            continue;
        }

        // Only add if value >= 128 (requires stateful mapping)
        if address_felt >= STATEFUL_MAPPING_START {
            if let Ok(storage_key) = StorageKey::try_from(address_felt) {
                alias_keys.insert(storage_key);
            }
        }
    }

    // Process accessed class hashes
    for class_hash in accessed_classes {
        let class_hash_felt: Felt = class_hash.0;

        // Skip if it's address 0x1
        if class_hash_felt == Felt::ONE {
            continue;
        }

        // Only add if value >= 128 (requires stateful mapping)
        if class_hash_felt >= STATEFUL_MAPPING_START {
            if let Ok(storage_key) = StorageKey::try_from(class_hash_felt) {
                alias_keys.insert(storage_key);
            }
        }
    }

    // Process existing storage keys from all contracts
    for (contract_addr, storage_keys) in accessed_keys_by_address.iter() {
        for storage_key in storage_keys {
            let contract_felt: Felt = (*(contract_addr)).into();

            // Skip if it's address 0x1
            if contract_felt == Felt::ONE || contract_felt == Felt::TWO {
                continue;
            }

            let key_felt: Felt = (*storage_key).into();

            // Only add if value >= 128 (requires stateful mapping)
            if key_felt >= STATEFUL_MAPPING_START {
                alias_keys.insert(*storage_key);
            }
            if contract_felt >= STATEFUL_MAPPING_START {
                alias_keys.insert(*storage_key);
            }
        }
    }

    // Add all qualifying keys to the alias contract (address 0x2)
    if !alias_keys.is_empty() {
        accessed_keys_by_address
            .entry(alias_contract_address)
            .or_default()
            .extend(alias_keys);

        log::debug!(
            "Added {} keys to alias contract (0x2) for storage mapping",
            accessed_keys_by_address
                .get(&alias_contract_address)
                .unwrap()
                .len()
        );
    }
}

pub async fn collect_single_block_info(
    block_number: u64,
    rpc_client: RpcClient,
) -> (
    OsBlockInput,
    BTreeMap<CompiledClassHash, CasmContractClass>,
    BTreeMap<CompiledClassHash, ContractClass>,
    HashSet<ContractAddress>,
    HashSet<ClassHash>,
    HashMap<ContractAddress, HashSet<StorageKey>>,
    Option<BlockId>,
) {
    log::debug!("Starting block info collection for block {}", block_number);
    let block_id = BlockId::Number(block_number);
    let previous_block_id = if block_number == 0 {
        None
    } else {
        Some(BlockId::Number(block_number - 1))
    };
    log::debug!(
        "Block IDs configured: current={}, previous={:?}",
        block_number,
        previous_block_id
            .map(|id| format!("{:?}", id))
            .unwrap_or("None".to_string())
    );

    // Step 1: build the block context
    log::debug!("Getting chain ID");
    let res = rpc_client.starknet_rpc().chain_id().await;
    log::debug!("Chain ID response: {:?}", res);
    let chain_id = chain_id_from_felt(res.expect("issue here"));
    log::debug!("Provider's chain_id: {}", chain_id);
    log::debug!("Chain ID retrieved: {}", chain_id);

    log::debug!("Fetching Step 2: Fetching block with transactions...");
    let block_with_txs = match rpc_client
        .starknet_rpc()
        .get_block_with_txs(block_id)
        .await
        .expect("block with txns issue")
    {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    log::debug!(
        "Successfully Block with {} transactions fetched",
        block_with_txs.transactions.len()
    );

    let starknet_version = StarknetVersion::V0_14_0; // TODO: get it from the txns itself
    log::debug!("Starknet version: {:?}", starknet_version);
    log::debug!(" Starknet version set to: {:?}", starknet_version);

    log::debug!("  Step 3: Fetching previous block...");
    let previous_block = match previous_block_id {
        Some(previous_block_id) => match rpc_client
            .starknet_rpc()
            .get_block_with_tx_hashes(previous_block_id)
            .await
            .expect("block with txn hashes issue")
        {
            MaybePendingBlockWithTxHashes::Block(block_with_txs) => Some(block_with_txs),
            MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                panic!("Block is still pending!");
            }
        },
        None => None,
    };

    // We only need to get the older block number and hash. No need to fetch all the txs
    // This is a workaorund to catch the case where the block number is less than the buffer and still preserve the check
    // The OS will also handle the case where the block number is less than the buffer.
    let older_block_number = block_number.saturating_sub(STORED_BLOCK_HASH_BUFFER);

    let older_block = match rpc_client
        .starknet_rpc()
        .get_block_with_tx_hashes(BlockId::Number(older_block_number))
        .await
        .expect("issue with older block number indeed")
    {
        MaybePendingBlockWithTxHashes::Block(block_with_txs_hashes) => block_with_txs_hashes,
        MaybePendingBlockWithTxHashes::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    let old_block_number = Felt::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    log::debug!(
        "previous block: {:?}, older block: {:?}",
        previous_block,
        older_block
    );
    log::debug!("Successfully Previous and older blocks fetched");

    log::debug!("  Step 4: Building block context...");
    let block_context = build_block_context(chain_id.clone(), &block_with_txs, starknet_version)
        .expect("issue while building the context");
    log::info!("Successfully Block context built successfully");

    log::debug!(" Step 5: Getting transaction traces...");
    let traces = rpc_client
        .starknet_rpc()
        .trace_block_transactions(block_id)
        .await
        .expect("Failed to get block tx traces");
    log::debug!("Successfully Got {} transaction traces", traces.len());

    // let file_path = "debug/blast_1309265.json";
    // log::debug!("Reading traces from file: {}", file_path);
    // let file_content = std::fs::read_to_string(file_path)
    //         .expect(&format!("Failed to read traces file: {}", file_path));
    // let traces: Vec<TransactionTraceWithHash> = serde_json::from_str(&file_content)
    //     .expect(&format!("Failed to parse traces JSON from file: {}", file_path));

    // log::debug!("Successfully Read {} traces from file", traces.len());

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    log::debug!(" Step 6: Extracting accessed contracts and classes...");
    let (mut accessed_addresses_felt, accessed_classes_felt) =
        get_subcalled_contracts_from_tx_traces(&traces);


    log::debug!(" Step 7: Getting formatted state update...");

    // panic!("time out");
    // log::debug!("formatted state update is: {:?}", processed_state_update);
    log::info!("Successfully State update processed successfully");
    log::debug!("Converting transactions to blockifier format...");
    let mut txs = Vec::new();
    for (i, (tx, trace)) in block_with_txs
        .transactions
        .iter()
        .zip(traces.iter())
        .enumerate()
    {
        let transaction = starknet_rs_to_blockifier(
            tx,
            trace,
            &block_context.block_info().gas_prices,
            &rpc_client,
            block_number,
            chain_id.clone(),
        )
        .await
        .expect("core to blockifier txn failed");
        txs.push(transaction);
        if (i + 1) % 10 == 0 || i == block_with_txs.transactions.len() - 1 {
            log::info!(
                "  📝 Converted {}/{} transactions",
                i + 1,
                block_with_txs.transactions.len()
            );
        }
    }
    log::info!("Successfully All transactions converted to blockifier format");

    let blockifier_txns: Vec<_> = txs
        .iter()
        .map(|txn_result| txn_result.blockifier_tx.clone())
        .collect();
    let starknet_api_txns: Vec<_> = txs
        .iter()
        .map(|txn_result| txn_result.starknet_api_tx.clone())
        .collect();

    let _block_number_hash_pair = maybe_dummy_block_hash_and_number(BlockNumber(block_number));

    log::debug!(" Step 9: Creating transaction executor...");
    let config = TransactionExecutorConfig::default();
    let blockifier_state_reader = AsyncRpcStateReader::new(
        rpc_client.clone(),
        previous_block_id.expect("previous block id is required"),
    );
    // let mut executor = TransactionExecutor::pre_process_and_create(
    //     blockifier_state_reader,
    //     block_context.clone(),
    //     block_number_hash_pair,
    //     config,
    // )
    //     .expect("Failed to create transaction executor.");

    let mut tmp_executor = TransactionExecutor::new(
        CachedState::new(blockifier_state_reader),
        block_context.clone(),
        config,
    );
    log::debug!("Successfully Transaction executor created");

    log::debug!("Executing {} transactions...", blockifier_txns.len());
    let execution_deadline = None;
    let execution_outputs: Vec<_> = tmp_executor
        .execute_txs(&blockifier_txns, execution_deadline)
        .into_iter()
        .collect::<Result<_, TransactionExecutorError>>()
        .expect("Unexpected error during execution.");
    log::info!("Successfully All transactions executed");

    let txn_execution_infos: Vec<TransactionExecutionInfo> = execution_outputs
        .into_iter()
        .map(|(execution_info, _)| execution_info)
        .collect();

    log::debug!("sierra gas is: {:?}", txn_execution_infos[0].receipt.resources.computation.sierra_gas);

    // write_serializable_to_file(&txn_execution_infos, &format!("debug/mainnet_txn_execution_info_{}.json", block_number), None).expect("Failed to write traces to file");

    // panic!("for now");
    let central_txn_execution_infos: Vec<CentralTransactionExecutionInfo> = txn_execution_infos
        .clone()
        .into_iter()
        .map(|execution_info| execution_info.clone().into())
        .collect();

    write_serializable_to_file(
        &central_txn_execution_infos,
        &format!("debug/mainnet_central_txn_info_{}.json", block_number),
        None,
    )
    .expect("Failed to write traces to file");

    // central_txn_execution_infos[0].actual_fee  = Fee(central_txn_execution_infos[0].actual_fee.0 - 644127000000000);
    // panic!("temp");

    log::debug!("  Step 11: Getting accessed keys...");
    let mut accessed_keys_by_address =
        get_accessed_keys_with_block_hash(&txn_execution_infos, old_block_number);
    log::debug!(
        "Successfully Got accessed keys for {} contracts",
        accessed_keys_by_address.len()
    );

    accessed_addresses_felt.extend(
        accessed_keys_by_address
            .keys()
            .map(|contract_addr| {
                let felt: Felt = (*contract_addr).into();
                Felt252::from(felt)
            })
    );

    let processed_state_update = get_formatted_state_update(
        &rpc_client,
        previous_block_id,
        block_id,
        accessed_addresses_felt.clone(),
        accessed_classes_felt.clone(),
    )
        .await
        .expect("issue while calling formatted state update");
    log::debug!("they keys of the compiled class hash is: {:?}", processed_state_update.compiled_classes.keys());
    log::debug!("they keys of the decprecated class hash is: {:?}", processed_state_update.deprecated_compiled_classes.keys());
    log::debug!("they keys of the compiled class hash is: {:?}", processed_state_update.class_hash_to_compiled_class_hash);

    // Convert Felt252 to proper types
    let accessed_addresses: HashSet<ContractAddress> = accessed_addresses_felt
        .iter()
        .map(|felt| ContractAddress::try_from(*felt).expect("Invalid contract address"))
        .collect();

    let mut accessed_classes: HashSet<ClassHash> = accessed_classes_felt
        .iter()
        .map(|felt| ClassHash(*felt))
        .collect();

    // log::debug!(">>>> classes from the traces are: {:?}", accessed_classes);
    // panic!("temp");
    log::debug!(
        "Successfully Found {} accessed addresses and {} accessed classes",
        accessed_addresses.len(),
        accessed_classes.len()
    );

    log::debug!("the addressea are: {:?}", accessed_addresses);
    log::debug!("the classes are: {:?}", accessed_classes);

    // panic!("temp");

    // Populate accessed_keys_by_address with special address 0x2 based on accessed addresses, classes, and storage mapping
    populate_alias_contract_keys(
        &accessed_addresses,
        &accessed_classes,
        &mut accessed_keys_by_address,
    );

    log::debug!("  Step 11b: Fetching storage proofs...");
    let storage_proofs = get_storage_proofs(&rpc_client, block_number, &accessed_keys_by_address)
        .await
        .expect("Failed to fetch storage proofs");
    log::info!("Successfully Got {} storage proofs", storage_proofs.len());

    log::debug!(" Step 12: Fetching previous storage proofs...");
    // TODO: add these keys to the accessed keys as well
    let previous_storage_proofs = match previous_block_id {
        Some(BlockId::Number(previous_block_id)) => {
            get_storage_proofs(&rpc_client, previous_block_id, &accessed_keys_by_address)
                .await
                .expect("Failed to fetch storage proofs")
        }
        None => get_storage_proofs(&rpc_client, 0, &accessed_keys_by_address)
            .await
            .expect("Failed to fetch storage proofs"),
        _ => {
            let mut map = HashMap::new();
            // We add a default proof for the block hash contract
            map.insert(
                Felt::ONE,
                PathfinderProof {
                    state_commitment: Default::default(),
                    class_commitment: None,
                    contract_commitment: Default::default(),
                    contract_proof: Vec::new(),
                    contract_data: None,
                },
            );
            map
        }
    };
    log::debug!(
        "Successfully Got {} previous storage proofs",
        previous_storage_proofs.len()
    );

    log::debug!(" Step 13: Processing contract storage commitments...");
    let mut contract_address_to_class_hash = HashMap::new();
    let mut address_to_storage_commitment_info: HashMap<ContractAddress, CommitmentInfo> =
        HashMap::new();

    for (contract_address, storage_proof) in storage_proofs.clone() {
        let contract_address: Felt = contract_address;
        let previous_storage_proof = previous_storage_proofs
            .get(&contract_address)
            .expect("failed to find previous storage proof");
        let previous_contract_commitment_facts = format_commitment_facts(
            &previous_storage_proof
                .clone()
                .contract_data
                .unwrap()
                .storage_proofs,
        );
        let current_contract_commitment_facts =
            format_commitment_facts(&storage_proof.clone().contract_data.unwrap().storage_proofs);
        // log::debug!("contract_address: {:?}, previous storage proof is: {:?}", contract_address, previous_contract_commitment_facts);
        // log::debug!("contract_address: {:?}, current storage proof is: {:?}", contract_address, current_contract_commitment_facts);
        let global_contract_commitment_facts: HashMap<HashOutput, Vec<Felt252>> =
            previous_contract_commitment_facts
                .into_iter()
                .chain(current_contract_commitment_facts)
                .map(|(key, value)| (HashOutput(key), value))
                .collect();

        // log::debug!("the global contract commitment facts turns out to be: {:?}", global_contract_commitment_facts);
        let previous_contract_storage_root: Felt = previous_storage_proof
            .contract_data
            .as_ref()
            .map(|contract_data| contract_data.root)
            .unwrap_or(Felt::ZERO);

        let current_contract_storage_root: Felt = storage_proof
            .contract_data
            .as_ref()
            .map(|contract_data| contract_data.root)
            .unwrap_or(Felt::ZERO);

        let contract_state_commitment_info = CommitmentInfo {
            previous_root: HashOutput(previous_contract_storage_root),
            updated_root: HashOutput(current_contract_storage_root),
            tree_height: SubTreeHeight(251),
            commitment_facts: global_contract_commitment_facts,
        };

        address_to_storage_commitment_info.insert(
            ContractAddress::try_from(contract_address).unwrap(),
            contract_state_commitment_info,
        );

        log::debug!(
            "Storage root 0x{:x} for contract 0x{:x} and same root in HashOutput would be: {:?}",
            Into::<Felt252>::into(previous_contract_storage_root),
            contract_address,
            HashOutput(previous_contract_storage_root)
        );
        log::debug!(
            "the contract address: {:?} and the block-id: {:?}",
            contract_address,
            block_id
        );

        // TODO: Check this special case handling once again - why does contract address 0x1 need class hash 0x0?
        let class_hash = if contract_address == Felt::ONE || contract_address == Felt::TWO {
            log::debug!("🔧 Special case: Contract address 0x1 detected, setting class hash to 0x0 without RPC call");
            Felt::ZERO
        } else {
            rpc_client
                .starknet_rpc()
                .get_class_hash_at(block_id, contract_address)
                .await
                .expect("issue with the class hash thingy")
        };

        contract_address_to_class_hash.insert(contract_address, class_hash);
    }
    log::info!(
        "Successfully Processed {} contract storage commitments",
        address_to_storage_commitment_info.len()
    );

    let compiled_classes = processed_state_update.compiled_classes;
    let deprecated_compiled_classes = processed_state_update.deprecated_compiled_classes;
    let declared_class_hash_component_hashes: HashMap<ClassHash, ContractClassComponentHashes> =
        processed_state_update
            .declared_class_hash_component_hashes
            .into_iter()
            .map(|(class_hash, component_hashes)| {
                (ClassHash(class_hash), component_hashes.to_os_format())
            })
            .collect();

    let class_hash_to_compiled_class_hash =
        processed_state_update.class_hash_to_compiled_class_hash;
    // query storage proofs for each accessed contract
    let class_hashes: Vec<&Felt252> = class_hash_to_compiled_class_hash.keys().collect();
    log::debug!(
        "  Step 14: Fetching class proofs for {} class hashes... and the class hashs are: {:?}",
        class_hashes.len(),
        class_hashes
    );
    // TODO: we fetch proofs here for block-1, but we probably also need to fetch at the current
    //       block, likely for contracts that are deployed in this block
    let class_proofs = get_class_proofs(&rpc_client, block_number, &class_hashes[..])
        .await
        .expect("Failed to fetch class proofs");
    log::debug!("Successfully Got {} class proofs", class_proofs.len());

    // before fetching the class proof at previous block, we can remove the ones which are declared in the new one
    // class_hashes.retain(|&x| !declared_class_hash_component_hashes.contains_key(&ClassHash(*x)));
    accessed_classes.extend(declared_class_hash_component_hashes.keys());
    log::debug!(" Step 15: Fetching previous class proofs...");
    let previous_class_proofs = match previous_block_id {
        Some(BlockId::Number(previous_block_id)) => {
            get_class_proofs(&rpc_client, previous_block_id, &class_hashes[..])
                .await
                .expect("Failed to fetch previous class proofs")
        }
        _ => Default::default(),
    };
    log::debug!(
        "Successfully Got {} previous class proofs",
        previous_class_proofs.len()
    );
    log::info!("Successfully got class proofs");

    // We can extract data from any storage proof, use the one of the block hash contract
    let block_hash_storage_proof = storage_proofs
        .get(&Felt::ONE)
        .expect("there should be a storage proof for the block hash contract");
    let previous_block_hash_storage_proof = previous_storage_proofs
        .get(&Felt::ONE)
        .expect("there should be a previous storage proof for the block hash contract");

    // The root of the class commitment tree for previous and current block
    // Using requested storage proof instead of getting them from class proofs
    // If the block doesn't contain transactions, `class_proofs` will be empty
    // Pathfinder will send a None on class_commitment when the tree is not initialized, ie, root is zero
    let updated_root = block_hash_storage_proof
        .class_commitment
        .unwrap_or(Felt::ZERO);
    let previous_root = previous_block_hash_storage_proof
        .class_commitment
        .unwrap_or(Felt::ZERO);

    // On devnet and until block 10, the storage_root_idx might be None and that means that contract_proof is empty
    let previous_contract_trie_root = previous_block_hash_storage_proof.contract_commitment;
    let current_contract_trie_root = block_hash_storage_proof.contract_commitment;

    let previous_contract_proofs: Vec<_> = previous_storage_proofs
        .values()
        .map(|proof| proof.contract_proof.clone())
        .collect();
    let previous_state_commitment_facts = format_commitment_facts(&previous_contract_proofs);
    let current_contract_proofs: Vec<_> = storage_proofs
        .values()
        .map(|proof| proof.contract_proof.clone())
        .collect();
    let current_state_commitment_facts = format_commitment_facts(&current_contract_proofs);

    let global_state_commitment_facts: HashMap<_, _> = previous_state_commitment_facts
        .into_iter()
        .chain(current_state_commitment_facts)
        .map(|(k, v)| (HashOutput(k), v))
        .collect();

    let contract_state_commitment_info = CommitmentInfo {
        previous_root: HashOutput(previous_contract_trie_root),
        updated_root: HashOutput(current_contract_trie_root),
        tree_height: SubTreeHeight(251),
        commitment_facts: global_state_commitment_facts,
    };
    log::info!("Successfully State commitment computed");
    log::debug!(
        "Contract state commitment info is: {:?}",
        contract_state_commitment_info
    );

    log::debug!(" Step 16: Computing class commitments...");
    let contract_class_commitment_info = compute_class_commitment(
        &previous_class_proofs,
        &class_proofs,
        previous_root,
        updated_root,
    );
    log::info!("Successfully Class commitment computed");
    log::debug!(
        "Contract class commitment info is: {:?}",
        contract_class_commitment_info
    );

    log::debug!(" Step 17: Converting compiled classes to BTreeMap with CompiledClassHash keys...");
    let mut compiled_classes_btree: BTreeMap<CompiledClassHash, CasmContractClass> =
        BTreeMap::new();

    for (class_hash_felt, generic_class) in compiled_classes {
        log::debug!("class hash here is: {:?}", class_hash_felt);
        let class_hash = CompiledClassHash(class_hash_felt);
        let cairo_lang_class = generic_class
            .get_cairo_lang_contract_class()
            .expect("Failed to get cairo-lang contract class")
            .clone();
        log::debug!("class hash here is: {:?}", class_hash);
        //
        // // 1. First check the existing class_hash_to_compiled_class_hash mapping
        // let compiled_class_hash = if let Some(&existing_compiled_hash) = class_hash_to_compiled_class_hash.get(&class_hash) {
        //     mapping_hits += 1;
        //     let compiled_class_hash = CompiledClassHash(existing_compiled_hash.into());
        //     log::debug!("Successfully Found compiled class hash in mapping: {:?} -> {:?}", class_hash, compiled_class_hash);
        //     compiled_class_hash
        // } else {
        //     // 2. Fallback to RPC call if not in mapping
        //     rpc_calls_made += 1;
        //     log::debug!("⚠️  Class hash {:?} not found in mapping, making RPC call...", class_hash);
        //     let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), block_id);
        //     match state_reader.get_compiled_class_hash_async(class_hash).await {
        //         Ok(compiled_hash) => {
        //             log::debug!("Successfully RPC call succeeded: {:?} -> {:?}", class_hash, compiled_hash);
        //             compiled_hash
        //         }
        //         Err(e) => {
        //             log::debug!("❌ RPC call failed for class hash {:?}: {}", class_hash, e);
        //             continue; // Skip this class if we can't get compiled class hash
        //         }
        //     }
        // };

        compiled_classes_btree.insert(class_hash, cairo_lang_class);
    }

    let mut deprecated_compiled_classes_btree: BTreeMap<CompiledClassHash, ContractClass> =
        BTreeMap::new();

    for (class_hash_felt, generic_class) in deprecated_compiled_classes {
        let class_hash = CompiledClassHash(class_hash_felt);
        let starknet_api_class = generic_class
            .to_starknet_api_contract_class()
            .expect("Failed to convert to starknet-api contract class");

        // 1. First check the existing class_hash_to_compiled_class_hash mapping
        // let compiled_class_hash = if let Some(&existing_compiled_hash) = class_hash_to_compiled_class_hash.get(&class_hash) {
        //     deprecated_mapping_hits += 1;
        //     let compiled_class_hash = CompiledClassHash(existing_compiled_hash.into());
        //     log::debug!("Successfully Found deprecated compiled class hash in mapping: {:?} -> {:?}", class_hash, compiled_class_hash);
        //     compiled_class_hash
        // } else {
        //     // 2. Fallback to RPC call if not in mapping
        //     deprecated_rpc_calls_made += 1;
        //     log::debug!("⚠️  Deprecated class hash {:?} not found in mapping, making RPC call...", class_hash);
        //     let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), block_id);
        //     match state_reader.get_compiled_class_hash_async(class_hash).await {
        //         Ok(compiled_hash) => {
        //             log::debug!("Successfully Deprecated RPC call succeeded: {:?} -> {:?}", class_hash, compiled_hash);
        //             compiled_hash
        //         }
        //         Err(e) => {
        //             log::debug!("❌ Deprecated RPC call failed for class hash {:?}: {}", class_hash, e);
        //             continue; // Skip this class if we can't get compiled class hash
        //         }
        //     }
        // };

        deprecated_compiled_classes_btree.insert(class_hash, starknet_api_class);
    }

    log::debug!(" Deprecated classes stats: 0 mapping hits, 0 RPC calls made");
    log::debug!(
        "Successfully Converted {} compiled classes and {} deprecated classes",
        compiled_classes_btree.len(),
        deprecated_compiled_classes_btree.len()
    );

    log::debug!(" Step 18: Building final OsBlockInput...");
    let os_block_input = OsBlockInput {
        contract_state_commitment_info,
        contract_class_commitment_info,
        address_to_storage_commitment_info,
        transactions: starknet_api_txns,
        tx_execution_infos: central_txn_execution_infos,
        declared_class_hash_to_component_hashes: declared_class_hash_component_hashes,
        block_info: block_context.block_info().clone(),
        prev_block_hash: BlockHash(previous_block.unwrap().block_hash),
        new_block_hash: BlockHash(block_with_txs.block_hash),
        old_block_number_and_hash: Some((
            BlockNumber(older_block_number),
            BlockHash(old_block_hash),
        )),
    };

    log::debug!(
        " collect_single_block_info: Completed successfully for block {}",
        block_number
    );
    (
        os_block_input,
        compiled_classes_btree,
        deprecated_compiled_classes_btree,
        accessed_addresses,
        accessed_classes,
        accessed_keys_by_address,
        previous_block_id,
    )
}
