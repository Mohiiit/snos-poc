use log::{error, info};
use snos_core::{generate_pie, ChainConfig, OsHintsConfiguration, PieGenerationInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    info!("🚀 Starting SNOS PoC application with clean architecture");

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: "https://pathfinder-snos.d.karnot.xyz".to_string(),
        blocks: vec![1872869], // 1872869 -> l1_handler, 1873475-> declare, 1873675 -> deploy account (from sepolia)
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
