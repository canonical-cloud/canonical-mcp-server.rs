use canonical_orm_core::{CapabilityProfile, DualOrmContext};
use std::{env, error::Error, io};

const AUDIT_DATABASE_URL_ENV: &str = "CANONICAL_AUDIT_DATABASE_URL";

pub(crate) async fn verify_from_env() -> Result<(), Box<dyn Error>> {
    if env::var_os("DATABASE_URL").is_some() {
        return Err(io::Error::other(
            "generic DATABASE_URL is forbidden for MCP persistence; use CANONICAL_AUDIT_DATABASE_URL",
        )
        .into());
    }

    let Ok(database_url) = env::var(AUDIT_DATABASE_URL_ENV) else {
        tracing::info!(
            dual_orm_verified = false,
            "CANONICAL_AUDIT_DATABASE_URL unset; persistence not configured"
        );
        return Ok(());
    };
    if database_url.trim().is_empty() {
        return Err(io::Error::other("CANONICAL_AUDIT_DATABASE_URL must not be empty").into());
    }

    let context =
        DualOrmContext::connect_read_only(&database_url, CapabilityProfile::WorkerReadOnly).await?;
    context.ping_both().await?;
    context.assert_catalog_congruence().await?;
    tracing::info!(
        dual_orm_verified = true,
        tenant_table = canonical_lib::audit_data::table::TENANTS,
        "audit dual ORM catalog verified"
    );
    Ok(())
}
