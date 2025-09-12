use clap::Parser;
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

// sepolia info:
//
// 🔍 COMPILED CLASS HASH INCONSISTENT (2 blocks)
// ----------------------------------------
//   Block  994169:    2.5KB [exact_match] - error_blocks_994169.txt
//   Block  994172:    2.5KB [exact_match] - error_blocks_994172.txt
//
// 🔍 L1 GAS UNREACHABLE ERROR (195 blocks)
// ----------------------------------------
//   Block  926808:    0.3KB [l1_gas_zero_constraint] - error_blocks_926808.txt
//   Block  930591:    0.3KB [l1_gas_zero_constraint] - error_blocks_930591.txt
//   Block  934517:    0.3KB [l1_gas_zero_constraint] - error_blocks_934517.txt
//   Block  934558:    0.3KB [l1_gas_zero_constraint] - error_blocks_934558.txt
//   Block  934584:    0.3KB [l1_gas_zero_constraint] - error_blocks_934584.txt
//   Block  940399:    0.3KB [l1_gas_zero_constraint] - error_blocks_940399.txt
//   Block  940976:    0.3KB [l1_gas_zero_constraint] - error_blocks_940976.txt
//   Block  941423:    0.3KB [l1_gas_zero_constraint] - error_blocks_941423.txt
//   Block  941939:    0.3KB [l1_gas_zero_constraint] - error_blocks_941939.txt
//   Block  941972:    0.3KB [l1_gas_zero_constraint] - error_blocks_941972.txt
//   Block  941987:    0.3KB [l1_gas_zero_constraint] - error_blocks_941987.txt
//   Block  942032:    0.3KB [l1_gas_zero_constraint] - error_blocks_942032.txt
//   Block  942054:    0.3KB [l1_gas_zero_constraint] - error_blocks_942054.txt
//   Block  942086:    0.3KB [l1_gas_zero_constraint] - error_blocks_942086.txt
//   Block  942104:    0.3KB [l1_gas_zero_constraint] - error_blocks_942104.txt
//   ... and 180 more blocks
//
// 🔍 COMPILED CLASS BUILD ERROR (2 blocks)
// ----------------------------------------
//   Block 1004270:    0.4KB [compiled_class_build_issue] - error_blocks_1004270.txt
//   Block 1023098:    0.4KB [compiled_class_build_issue] - error_blocks_1023098.txt
//
// 🔍 GATEWAY TIMEOUT ERRORS (1 blocks)
// ----------------------------------------
//   Block 1041119:    0.6KB [gateway_502_bad] - error_blocks_1041119.txt
//
// 🔍 OTHER ERRORS (12 blocks)
// ----------------------------------------
//   Block  927143:    6.7KB [unmatched] - error_blocks_927143.txt
//   Block  940168:    8.8KB [unmatched] - error_blocks_940168.txt
//   Block 1023234:    0.5KB [unmatched] - error_blocks_1023234.txt
//   Block 1023294:    0.5KB [unmatched] - error_blocks_1023294.txt
//   Block 1025049:    4.5KB [unmatched] - error_blocks_1025049.txt
//   Block 1038850:    0.5KB [unmatched] - error_blocks_1038850.txt
//   Block 1043384:    5.6KB [unmatched] - error_blocks_1043384.txt
//   Block 1043767:    7.9KB [unmatched] - error_blocks_1043767.txt
//   Block 1060745:    8.8KB [unmatched] - error_blocks_1060745.txt
//   Block 1061489:    8.8KB [unmatched] - error_blocks_1061489.txt
//   Block 1061495:    8.8KB [unmatched] - error_blocks_1061495.txt
//   Block 1067436:    4.4KB [unmatched] - error_blocks_1067436.txt

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "snos-poc")]
#[command(about = "SNOS PoC - Starknet OS Proof of Concept for block processing")]
struct Cli {
    /// RPC URL to connect to
    #[arg(short, long, default_value = "https://pathfinder-mainnet.d.karnot.xyz")]
    rpc_url: String,

    /// Block number(s) to process
    #[arg(short, long, value_delimiter = ',')]
    blocks: Vec<u64>,

    /// Output path for the PIE file
    #[arg(short, long)]
    output: Option<String>,

    /// Chain configuration (defaults to Sepolia)
    #[arg(long, default_value = "sepolia")]
    chain: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let cli = Cli::parse();

    info!("🚀 Starting SNOS PoC application with clean architecture");

    // Validate that at least one block is provided
    if cli.blocks.is_empty() {
        error!("❌ At least one block number must be provided");
        std::process::exit(1);
    }

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: cli.rpc_url.clone(),
        blocks: cli.blocks.clone(),
        chain_config: ChainConfig::default(), // Uses Sepolia defaults for now
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: cli.output.clone(),
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
