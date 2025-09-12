use log::{error, info};
use snos_core::{generate_pie, ChainConfig, OsHintsConfiguration, PieGenerationInput};

// mainnet 1943728 -> compiled class issue -> computed hash -> 0x0312e8d8d5161bf0704e26f3f40195b36bb3696bcd986a48758181732877e1cb and expected hash -> 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918
// did some changes to the abi and stuff got new computed hash -> 0x0708805f9138fb6e4b209247c8b5ec46463b01cedb029392fd86d3769a314367 and expected is same -> 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918
// after some more changes we got computed hash -> 0x07fd53e69c49d1a43c4d690e4b058886596824229674e04734babc31908c10c8
// block 1943728 is now passing, after we sorted the attributes in order, same as it's done in the pathfinder
// block 1943729 was also failing with the same error, testing that now
// 1943729 failed with something else now, looking into it!

// 🏷️  COMPILED CLASS HASH INCONSISTENT (some fixed, but getting new error of MAX_HIGH const not found)
//    Description: Computed compiled_class_hash is inconsistent
//    Count: 1018 (53.4%)
//    Blocks: 1943728, 1943729, 1943787, 1943792, 1943808, 1943878, 1943879, 1943885, 1943906, 1943917, ... and 1008 more
//
// 🏷️  MISSING FIELD KIND (seems fixed, one block done, testing on more now)(tested two blocks and it worked for now)
//    Description: Missing field `kind` (SerdeError)
//    Count: 326 (17.1%)
//    Blocks: 1943731, 1943799, 1943845, 1943913, 1943938, 1944008, 1944076, 1944077, 1944146, 1944215, ... and 316 more
//
// 🏷️  TRIE VALUE MISMATCH
//    Description: Trie value mismatch (DiffAssertValues with patricia.cairo)
//    Count: 549 (28.8%)
//    Blocks: 1943743, 1943747, 1943750, 1943752, 1943753, 1943756, 1943768, 1943773, 1943774, 1943775, ... and 539 more
//
// 🏷️  OTHER ERRORS
//    Description: All other uncategorized errors
//    Count: 10 (0.6%)
//    Blocks: 1944976, 1945751, 1945757, 1945779, 1945788, 1945818, 1945833, 1945850, 1946082, 1946705, ... and 2 more

// pub const MAINNET_RANGE_WHERE_RE_EXECUTION_IS_IMPOSSIBLE_START: BlockNumber =
//     BlockNumber::new_or_panic(1943704);
// pub const MAINNET_RANGE_WHERE_RE_EXECUTION_IS_IMPOSSIBLE_END: BlockNumber =
//     BlockNumber::new_or_panic(1952704);
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    info!("🚀 Starting SNOS PoC application with clean architecture");

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: "https://pathfinder-mainnet.d.karnot.xyz".to_string(),
        blocks: vec![1952705], // 1872869 -> l1_handler, 1873475-> declare, 1873675 -> deploy account (from sepolia)
        chain_config: ChainConfig::default(), // Uses Sepolia defaults
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: None,
    };

    info!("📋 Configuration:");
    info!("  RPC URL: {}", input.rpc_url);
    info!("  Blocks: {:?}", input.blocks);
    info!("  Chain ID: {:?}", input.chain_config.chain_id);
    info!("  Output: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok(result) => {
            info!("🎉 PIE generation completed successfully!");
            info!("  Blocks processed: {:?}", result.blocks_processed);
            if let Some(output_path) = result.output_path {
                info!("  Output written to: {}", output_path);
            }
        }
        Err(e) => {
            error!("❌ PIE generation failed: {}", e);
            return Err(e.into());
        }
    }

    info!("✅ SNOS execution completed successfully!");
    Ok(())
}
