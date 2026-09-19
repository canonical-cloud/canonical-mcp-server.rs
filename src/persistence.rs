use canonical_orm_core::{CapabilityProfile, DualOrmContext};
use std::{env, error::Error};

pub(crate) async fn verify_from_env() -> Result<bool, Box<dyn Error>> {
    let Ok(database_url) = env::var("DATABASE_URL") else {
        return Ok(false);
    };
    if database_url.trim().is_empty() {
        return Ok(false);
    }

    let context = DualOrmContext::connect_read_only(&database_url, CapabilityProfile::WorkerReadOnly)
        .await?;
    context.ping_both().await?;
    context.assert_catalog_congruence().await?;
    Ok(true)
}
