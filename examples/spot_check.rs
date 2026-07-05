//! Phase 1 definition-of-done check: hit five generated endpoints against
//! live ESI and print a one-line summary of each response.
//!
//! Run with: `cargo run --example spot_check`

use eve_esi_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .user_agent("eve-esi spot-check (jay.nejati@outlook.com)")
        .build()?;

    let status = client.get_status().send().await?;
    println!(
        "1. GET /status              -> {} players online, server {}",
        status.players, status.server_version
    );

    let alliances = client.get_alliances().send().await?;
    println!(
        "2. GET /alliances           -> {} alliances, first id {:?}",
        alliances.len(),
        alliances.first()
    );

    let prices = client.get_markets_prices().send().await?;
    println!(
        "3. GET /markets/prices      -> {} type prices",
        prices.len()
    );

    let systems = client.get_universe_systems().send().await?;
    println!(
        "4. GET /universe/systems    -> {} solar systems",
        systems.len()
    );

    let insurance = client.get_insurance_prices().send().await?;
    println!(
        "5. GET /insurance/prices    -> {} insured hull types",
        insurance.len()
    );

    Ok(())
}
