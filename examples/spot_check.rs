//! Phase 1 definition-of-done check: hit six generated endpoints against
//! live ESI and print a one-line summary of each response.
//!
//! Run with: `cargo run --example spot_check`

use eve_esi_client::{types::SovereigntySystemsSolarsystemClaim as Claim, Client};

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

    // Each claim is a oneOf union; this line would show 0 alliance claims if
    // the generated enum stopped discriminating between its variants.
    let sovereignty = client.get_sovereignty_systems().send().await?;
    let (mut faction, mut alliance, mut unclaimed) = (0, 0, 0);
    for system in &sovereignty.solar_systems {
        match system.claim {
            Claim::Faction(_) => faction += 1,
            Claim::Alliance(_) => alliance += 1,
            Claim::Unclaimed(_) => unclaimed += 1,
        }
    }
    println!(
        "6. GET /sovereignty/systems -> {} systems: {faction} faction, {alliance} alliance, {unclaimed} unclaimed",
        sovereignty.solar_systems.len()
    );

    Ok(())
}
