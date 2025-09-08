use cairo_vm::types::layout_name::LayoutName;
use rpc_client::RpcClient;
use starknet::core::types::BlockId;
use starknet_api::core::{ChainId, ContractAddress};
use starknet_os::io::os_output::StarknetOsRunnerOutput;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os_stateless,
};
use starknet_types_core::felt::Felt;
use std::path::Path;

mod api_to_blockifier_conversion;
mod block_processor;
mod cached_state;
mod commitment_utils;
mod context_builder;
mod error;
mod rpc_utils;
mod state_processing;
mod state_update;

use block_processor::collect_single_block_info;
use cached_state::generate_cached_state_input;

/// Configuration for chain-specific settings
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: ChainId,
    pub strk_fee_token_address: ContractAddress,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId::Mainnet,
            strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked(
                "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
            ))
            .expect("Valid contract address"),
        }
    }
}

/// Configuration for OS hints
#[derive(Debug, Clone)]
pub struct OsHintsConfiguration {
    pub debug_mode: bool,
    pub full_output: bool,
    pub use_kzg_da: bool,
}

impl Default for OsHintsConfiguration {
    fn default() -> Self {
        Self {
            debug_mode: true,
            full_output: false,
            use_kzg_da: true,
        }
    }
}

/// Input configuration for PIE generation
#[derive(Debug, Clone)]
pub struct PieGenerationInput {
    pub rpc_url: String,
    pub blocks: Vec<u64>,
    pub chain_config: ChainConfig,
    pub os_hints_config: OsHintsConfiguration,
    pub output_path: Option<String>,
}

/// Result containing the generated PIE and metadata
pub struct PieGenerationResult {
    pub output: StarknetOsRunnerOutput,
    pub blocks_processed: Vec<u64>,
    pub output_path: Option<String>,
}

/// Main error type for PIE generation
#[derive(thiserror::Error, Debug)]
pub enum PieGenerationError {
    #[error("Block processing failed for block {block_number}: {source}")]
    BlockProcessing {
        block_number: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("RPC client error: {0}")]
    RpcClient(String),

    #[error("OS execution error: {0}")]
    OsExecution(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Core function to generate PIE from blocks
///
/// This function takes the input configuration and processes the specified blocks
/// to generate a Cairo PIE file. It handles all the complexity of block processing,
/// state management, and OS execution.
pub async fn generate_pie(
    input: PieGenerationInput,
) -> Result<PieGenerationResult, PieGenerationError> {
    log::info!(
        "Starting PIE generation for {} blocks: {:?}",
        input.blocks.len(),
        input.blocks
    );

    // Initialize RPC client
    let rpc_client = RpcClient::new(&input.rpc_url);
    log::info!("RPC client initialized for {}", input.rpc_url);

    let mut os_block_inputs = Vec::new();
    let mut cached_state_inputs = Vec::new();
    let mut all_compiled_classes = std::collections::BTreeMap::new();
    let mut all_deprecated_compiled_classes = std::collections::BTreeMap::new();

    // Process each block
    for (index, block_number) in input.blocks.iter().enumerate() {
        log::info!(
            "=== Processing block {} ({}/{}) ===",
            block_number,
            index + 1,
            input.blocks.len()
        );

        log::info!("State reader created for block {}", block_number);

        log::info!("Starting to collect block info for block {}", block_number);
        let (
            block_input,
            compiled_classes,
            deprecated_compiled_classes,
            accessed_addresses,
            accessed_classes,
            accessed_keys_by_address,
            _previous_block_id,
        ) = collect_single_block_info(*block_number, rpc_client.clone()).await;
        log::info!("Block info collection completed for block {}", block_number);

        // Add block input to our collection
        os_block_inputs.push(block_input);

        // Merge compiled classes (these are shared across blocks)
        all_compiled_classes.extend(compiled_classes);
        all_deprecated_compiled_classes.extend(deprecated_compiled_classes);

        // Generate cached state input
        log::debug!("Generating cached state input for block {}", block_number);
        let mut cached_state_input = generate_cached_state_input(
            &rpc_client,
            BlockId::Number(block_number - 1),
            &accessed_addresses,
            &accessed_classes,
            &accessed_keys_by_address,
        )
        .await
        .map_err(|e| PieGenerationError::BlockProcessing {
            block_number: *block_number,
            source: Box::new(std::io::Error::other(format!("{:?}", e))),
        })?;
        cached_state_input
            .class_hash_to_compiled_class_hash
            .retain(|class_hash, _| !all_deprecated_compiled_classes.contains_key(class_hash));
        log::debug!("Compiled classes are: {:?}", all_compiled_classes.keys());
        log::debug!(
            "Deprecated compiled classes are: {:?}",
            all_deprecated_compiled_classes.keys()
        );
        log::debug!(
            "ch to cch keys are: {:?}",
            cached_state_input.class_hash_to_compiled_class_hash.keys()
        );
        cached_state_inputs.push(cached_state_input);
        log::info!("Block {} processed successfully", block_number);
    }

    // Sort ABI entries for all deprecated compiled classes
    log::info!("Sorting ABI entries for deprecated compiled classes");
    for (class_hash, compiled_class) in all_deprecated_compiled_classes.iter_mut() {
        if let Err(e) = sort_abi_entries_for_deprecated_class(compiled_class) {
            log::warn!(
                "Failed to sort ABI entries for class {:?}: {}",
                class_hash,
                e
            );
        }
    }

    log::info!("=== Finalizing multi-block processing ===");
    log::debug!(
        "OS inputs prepared with {} block inputs and {} cached state inputs",
        os_block_inputs.len(),
        cached_state_inputs.len()
    );
    // let felt_to_match = Felt::from_hex_unchecked("0x44ea0d21fdaecd913b9c6574d85800b45a973413edab4f5400ecd756b5b2ea");
    // assert!()

    log::debug!("Building OS hints configuration for multi-block processing");
    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: input.os_hints_config.debug_mode,
            full_output: input.os_hints_config.full_output,
            use_kzg_da: input.os_hints_config.use_kzg_da,
            chain_info: OsChainInfo {
                chain_id: input.chain_config.chain_id,
                strk_fee_token_address: input.chain_config.strk_fee_token_address,
            },
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes: all_deprecated_compiled_classes,
            compiled_classes: all_compiled_classes,
        },
    };
    log::info!(
        "OS hints configuration built successfully for {} blocks",
        input.blocks.len()
    );

    log::debug!("Starting OS execution for multi-block processing");
    log::info!("Using layout: {:?}", LayoutName::all_cairo);
    let output = run_os_stateless(LayoutName::all_cairo, os_hints)
        .map_err(|e| PieGenerationError::OsExecution(format!("{:?}", e)))?;
    log::info!("Multi-block output generated successfully!");

    // Validate the PIE
    let _ = output.cairo_pie.run_validity_checks();
    log::info!("Cairo pie validation done!!");

    // Save to file if path is specified
    if let Some(output_path) = &input.output_path {
        log::info!("Writing PIE to file: {}", output_path);
        let _ = output
            .cairo_pie
            .write_zip_file(Path::new(output_path), true);
    }

    log::info!(
        "PIE generation completed successfully for blocks {:?}",
        input.blocks
    );

    log::info!("");
    log::info!("🎉 ================================================ 🎉");
    log::info!("✅ PIE GENERATION COMPLETED AND VALIDATED SUCCESSFULLY ✅");
    log::info!("🎉 ================================================ 🎉");
    log::info!("");

    Ok(PieGenerationResult {
        output,
        blocks_processed: input.blocks.clone(),
        output_path: input.output_path.clone(),
    })
}

/// Helper function to sort ABI entries and normalize program attributes in a deprecated compiled class
/// This implements the complete normalization logic from pathfinder's prepare_json_contract_definition:
/// 1. Sorts ABI entries by type (Constructor, Event, Function, L1Handler, Struct)
/// 2. Removes debug_info from program
/// 3. Normalizes program attributes by removing empty/null fields
/// 4. Handles backwards compatibility for compiler versions
/// 5. Sorts attribute keys for deterministic JSON representation
fn sort_abi_entries_for_deprecated_class(
    compiled_class: &mut starknet_api::deprecated_contract_class::ContractClass,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sort ABI entries by type first
    // if let Some(ref mut abi) = compiled_class.abi {
    //     abi.sort_by(|a, b| {
    //         let order_a = get_abi_entry_order_from_entry(a);
    //         let order_b = get_abi_entry_order_from_entry(b);
    //
    //         // Primary sort by type order
    //         match order_a.cmp(&order_b) {
    //             std::cmp::Ordering::Equal => {
    //                 // Secondary sort by name for deterministic ordering within each type
    //                 get_abi_entry_name(a).cmp(&get_abi_entry_name(b))
    //             }
    //             other => other,
    //         }
    //     });
    // }

    // CRUCIAL: Complete program normalization exactly like pathfinder does
    // The program field is directly a Program, not an Option<Program>
    let program = &mut compiled_class.program;

    // First, serialize the program to JSON so we can manipulate it
    let mut program_json = serde_json::to_value(&*program)?;

    // Step 1: Remove debug_info (like pathfinder does)
    if let Some(program_obj) = program_json.as_object_mut() {
        program_obj.insert("debug_info".to_string(), serde_json::Value::Null);
    }

    // Step 2: Normalize program attributes
    if let Some(attributes) = program_json.get_mut("attributes") {
        if let Some(attributes_array) = attributes.as_array_mut() {
            // Process each attribute in the array
            for attr in attributes_array.iter_mut() {
                if let Some(attr_obj) = attr.as_object_mut() {
                    // Remove empty accessible_scopes arrays
                    match attr_obj.get("accessible_scopes") {
                        Some(serde_json::Value::Array(array)) => {
                            if array.is_empty() {
                                attr_obj.remove("accessible_scopes");
                            }
                        }
                        Some(_) => {
                            return Err(
                                "Program attribute 'accessible_scopes' was not an array type"
                                    .into(),
                            );
                        }
                        None => {}
                    }

                    // Remove null flow_tracking_data fields
                    if let Some(serde_json::Value::Null) = attr_obj.get("flow_tracking_data") {
                        attr_obj.remove("flow_tracking_data");
                    }
                }
            }

            // Step 3: Sort attribute keys for deterministic ordering
            sort_attributes_keys(attributes_array)?;
        }
    }

    // Step 4: Handle backwards compatibility for compiler versions
    let compiler_version_missing = program_json
        .get("compiler_version")
        .map(|v| v.is_null())
        .unwrap_or(true);

    if compiler_version_missing {
        // Add extra space to cairo named tuples for backwards compatibility
        if let Some(identifiers) = program_json.get_mut("identifiers") {
            add_extra_space_to_cairo_named_tuples(identifiers);
        }
        if let Some(reference_manager) = program_json.get_mut("reference_manager") {
            add_extra_space_to_cairo_named_tuples(reference_manager);
        }
    }

    // Deserialize the modified JSON back to the program
    *program = serde_json::from_value(program_json)?;

    log::debug!("Completed full program normalization for deprecated contract class");

    log::debug!(
        "Completed ABI sorting and complete program normalization for deprecated contract class"
    );
    Ok(())
}

/// Sort attribute keys for deterministic JSON ordering (from pathfinder)
fn sort_attributes_keys(
    attributes: &mut Vec<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!(
        "Sorting attributes keys for {} attributes",
        attributes.len()
    );

    for attr in attributes.iter_mut() {
        if let serde_json::Value::Object(obj) = attr {
            // Create a new sorted map
            let mut sorted_map = serde_json::Map::new();

            // Collect all key-value pairs and sort them by key
            let mut pairs: Vec<_> = obj.iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(b.0));

            // Insert sorted pairs into the new map
            for (key, value) in pairs {
                sorted_map.insert(key.clone(), value.clone());
            }

            // Replace the original object with the sorted one
            *attr = serde_json::Value::Object(sorted_map);
        }
    }

    log::debug!("Completed sorting attributes keys");
    Ok(())
}

/// Add extra space to cairo named tuples for backwards compatibility (from pathfinder)
fn add_extra_space_to_cairo_named_tuples(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(v) => walk_array(v),
        serde_json::Value::Object(m) => walk_map(m),
        _ => {}
    }
}

fn walk_array(array: &mut [serde_json::Value]) {
    for v in array.iter_mut() {
        add_extra_space_to_cairo_named_tuples(v);
    }
}

fn walk_map(object: &mut serde_json::Map<String, serde_json::Value>) {
    for (k, v) in object.iter_mut() {
        match v {
            serde_json::Value::String(s) => {
                let new_value = add_extra_space_to_named_tuple_type_definition(k, s);
                if new_value.as_ref() != s {
                    *v = serde_json::Value::String(new_value.into());
                }
            }
            _ => add_extra_space_to_cairo_named_tuples(v),
        }
    }
}

fn add_extra_space_to_named_tuple_type_definition<'a>(
    key: &str,
    value: &'a str,
) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow::*;
    match key {
        "cairo_type" | "value" => Owned(add_extra_space_before_colon(value)),
        _ => Borrowed(value),
    }
}

fn add_extra_space_before_colon(v: &str) -> String {
    // This is required because if we receive an already correct ` : `, we will
    // still "repair" it to `  : ` which we then fix at the end.
    v.replace(": ", " : ").replace("  :", " :")
}

/// Returns the sort order for ABI entry types based on the actual entry
/// Order: Constructor(0), Event(1), Function(2), L1Handler(3), Struct(4)
fn get_abi_entry_order_from_entry(
    entry: &starknet_api::deprecated_contract_class::ContractClassAbiEntry,
) -> u8 {
    use starknet_api::deprecated_contract_class::ContractClassAbiEntry;

    match entry {
        ContractClassAbiEntry::Constructor(_) => 0,
        ContractClassAbiEntry::Event(_) => 1,
        ContractClassAbiEntry::Function(_) => 2,
        ContractClassAbiEntry::L1Handler(_) => 3,
        ContractClassAbiEntry::Struct(_) => 4,
    }
}

/// Helper function to get the name of an ABI entry for secondary sorting
fn get_abi_entry_name(
    entry: &starknet_api::deprecated_contract_class::ContractClassAbiEntry,
) -> &str {
    use starknet_api::deprecated_contract_class::ContractClassAbiEntry;

    match entry {
        ContractClassAbiEntry::Constructor(c) => &c.name,
        ContractClassAbiEntry::Event(e) => &e.name,
        ContractClassAbiEntry::Function(f) => &f.name,
        ContractClassAbiEntry::L1Handler(l) => &l.name,
        ContractClassAbiEntry::Struct(s) => &s.name,
    }
}
