use canonical_orm_core::{CapabilityProfile, DualOrmContext};
use std::{env, error::Error};

pub(crate) async fn verify_from_env() -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = env::var("DATABASE_URL") else {
        tracing::info!(
            dual_orm_verified = false,
            "DATABASE_URL unset; persistence not verified"
        );
        return Ok(());
    };
    if database_url.trim().is_empty() {
        tracing::info!(
            dual_orm_verified = false,
            "DATABASE_URL empty; persistence not verified"
        );
        return Ok(());
    }

    let context =
        DualOrmContext::connect_read_only(&database_url, CapabilityProfile::WorkerReadOnly).await?;
    context.ping_both().await?;
    context.assert_catalog_congruence().await?;
    tracing::info!(
        dual_orm_verified = true,
        tenant_table = canonical_lib::audit_data::table::TENANTS,
        "dual ORM catalog verified"
    );
    Ok(())
}
