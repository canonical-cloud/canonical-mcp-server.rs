//! Read-only Gmail/Google storage shadow evidence for Canonical Plus outbound safety.
//!
//! This adapter intentionally implements only fixed GET requests. It cannot send mail,
//! read message bodies, update Gmail settings, or accept caller-supplied URLs.
//!
//! OAuth token scopes:
//! - https://www.googleapis.com/auth/gmail.settings.basic
//! - https://www.googleapis.com/auth/drive.metadata.readonly
//!
//! The Gmail settings scope is used only through compiled GET endpoints for vacation
//! and send-as settings. The adapter never implements a Gmail write method.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use super::error_chain;

const VACATION_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/settings/vacation";
const SEND_AS_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs";
const DRIVE_ABOUT_URL: &str =
    "https://www.googleapis.com/drive/v3/about?fields=storageQuota%28limit%2Cusage%29";
const MAX_GOOGLE_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_STORAGE_FREE_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_STORAGE_FREE_BASIS_POINTS: u16 = 1_000;

pub const TOKEN_ENV: &str = "CANONICAL_GOOGLE_AUDIT_TOKEN";
pub const EXPECTED_SENDER_SHA256_ENV: &str = "CANONICAL_GMAIL_EXPECTED_SENDER_SHA256";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceState {
    Verified,
    NotApplicable,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerSenderHealthSnapshot {
    pub observed_at_unix_seconds: i64,
    pub source_ref_sha256: String,
    pub sender_identity_sha256: String,
    pub storage_used_bytes: Option<u64>,
    pub storage_limit_bytes: Option<u64>,
    pub vacation_responder_disabled: AssuranceState,
    pub reply_routing: AssuranceState,
    pub sender_auth: AssuranceState,
    pub inbox_placement: AssuranceState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailShadowReport {
    pub mode: &'static str,
    pub read_only: bool,
    pub send_capability: bool,
    pub worker_ready: bool,
    pub sender_identity_pinned: bool,
    pub storage_free_bytes: Option<u64>,
    pub storage_free_basis_points: Option<u16>,
    pub hold_reasons: Vec<&'static str>,
    pub worker_sender_health: WorkerSenderHealthSnapshot,
    pub required_oauth_scopes: [&'static str; 2],
}

struct SelectedSender {
    identity_sha256: String,
    verification_accepted: bool,
    reply_routing_verified: bool,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut out = String::with_capacity(64);
    for byte in digest {
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn normalized_email(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() > 320
        || value.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.matches('@').count() != 1
    {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(value)
}

fn selected_sender(
    send_as: &Value,
    expected_sender_sha256: Option<&str>,
) -> Result<SelectedSender, String> {
    let entries = send_as
        .get("sendAs")
        .and_then(Value::as_array)
        .ok_or_else(|| "Gmail send-as response omitted sendAs".to_string())?;

    let mut selected: Option<SelectedSender> = None;
    for entry in entries {
        let Some(raw_email) = entry.get("sendAsEmail").and_then(Value::as_str) else {
            continue;
        };
        let Some(email) = normalized_email(raw_email) else {
            continue;
        };
        let identity_sha256 = sha256_hex(email.as_bytes());
        let matches = expected_sender_sha256
            .map(|expected| expected == identity_sha256)
            .unwrap_or_else(|| entry.get("isPrimary").and_then(Value::as_bool) == Some(true));
        if !matches {
            continue;
        }
        if selected.is_some() {
            return Err(
                "Gmail send-as response has multiple matching sender identities".to_string(),
            );
        }

        let verification_accepted =
            entry.get("verificationStatus").and_then(Value::as_str) == Some("accepted");
        let reply_routing_verified = match entry.get("replyToAddress").and_then(Value::as_str) {
            None | Some("") => true,
            Some(reply_to) => normalized_email(reply_to).as_deref() == Some(email.as_str()),
        };

        selected = Some(SelectedSender {
            identity_sha256,
            verification_accepted,
            reply_routing_verified,
        });
    }

    selected.ok_or_else(|| {
        if expected_sender_sha256.is_some() {
            "configured sender identity is not present in Gmail send-as settings".to_string()
        } else {
            "Gmail send-as response has no unique primary sender".to_string()
        }
    })
}

fn vacation_state(vacation: &Value) -> AssuranceState {
    match vacation.get("enableAutoReply").and_then(Value::as_bool) {
        Some(false) => AssuranceState::Verified,
        Some(true) => AssuranceState::Failed,
        None => AssuranceState::Unknown,
    }
}

fn quota_values(about: &Value) -> (Option<u64>, Option<u64>) {
    let quota = about.get("storageQuota");
    let parse = |key: &str| {
        quota
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
    };
    (parse("usage"), parse("limit"))
}

fn storage_free(
    usage: Option<u64>,
    limit: Option<u64>,
) -> (Option<u64>, Option<u16>, Option<bool>) {
    let (Some(usage), Some(limit)) = (usage, limit) else {
        return (None, None, None);
    };
    if limit == 0 || usage > limit {
        return (Some(0), Some(0), Some(false));
    }

    let free = limit - usage;
    let basis_points = ((u128::from(free) * 10_000_u128) / u128::from(limit)) as u16;
    let safe = free >= MIN_STORAGE_FREE_BYTES && basis_points >= MIN_STORAGE_FREE_BASIS_POINTS;
    (Some(free), Some(basis_points), Some(safe))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestInput<'a> {
    observed_at_unix_seconds: i64,
    sender_identity_sha256: &'a str,
    storage_used_bytes: Option<u64>,
    storage_limit_bytes: Option<u64>,
    vacation_responder_disabled: AssuranceState,
    reply_routing: AssuranceState,
}

pub fn summarize(
    vacation: &Value,
    send_as: &Value,
    drive_about: &Value,
    observed_at_unix_seconds: i64,
    expected_sender_sha256: Option<&str>,
) -> Result<GmailShadowReport, String> {
    if observed_at_unix_seconds < 1 {
        return Err("observation timestamp must be positive".to_string());
    }
    if expected_sender_sha256.is_some_and(|value| !valid_sha256(value)) {
        return Err(format!(
            "{EXPECTED_SENDER_SHA256_ENV} must be a lowercase 64-character SHA-256 digest"
        ));
    }

    let sender = selected_sender(send_as, expected_sender_sha256)?;
    let vacation_responder_disabled = vacation_state(vacation);
    let reply_routing = if sender.verification_accepted && sender.reply_routing_verified {
        AssuranceState::Verified
    } else {
        AssuranceState::Failed
    };
    let (storage_used_bytes, storage_limit_bytes) = quota_values(drive_about);
    let (storage_free_bytes, storage_free_basis_points, storage_safe) =
        storage_free(storage_used_bytes, storage_limit_bytes);

    let digest_input = EvidenceDigestInput {
        observed_at_unix_seconds,
        sender_identity_sha256: &sender.identity_sha256,
        storage_used_bytes,
        storage_limit_bytes,
        vacation_responder_disabled,
        reply_routing,
    };
    let source_ref_sha256 = sha256_hex(
        &serde_json::to_vec(&digest_input)
            .map_err(|error| format!("cannot serialize shadow evidence: {error}"))?,
    );

    let worker_sender_health = WorkerSenderHealthSnapshot {
        observed_at_unix_seconds,
        source_ref_sha256,
        sender_identity_sha256: sender.identity_sha256,
        storage_used_bytes,
        storage_limit_bytes,
        vacation_responder_disabled,
        reply_routing,
        // Gmail settings do not prove SPF/DKIM/DMARC. Keep this fail-closed.
        sender_auth: AssuranceState::Unknown,
        inbox_placement: AssuranceState::NotApplicable,
    };

    let mut hold_reasons = Vec::new();
    if expected_sender_sha256.is_none() {
        hold_reasons.push("expected_sender_identity_unpinned");
    }
    match storage_safe {
        Some(true) => {}
        Some(false) => hold_reasons.push("storage_quota_unsafe"),
        None => hold_reasons.push("storage_quota_unknown"),
    }
    match worker_sender_health.vacation_responder_disabled {
        AssuranceState::Verified => {}
        AssuranceState::Failed => hold_reasons.push("vacation_responder_enabled"),
        AssuranceState::Unknown | AssuranceState::NotApplicable => {
            hold_reasons.push("vacation_responder_unknown");
        }
    }
    if worker_sender_health.reply_routing != AssuranceState::Verified {
        hold_reasons.push("reply_routing_unverified");
    }
    hold_reasons.push("sender_auth_not_proven_by_gmail_api");

    Ok(GmailShadowReport {
        mode: "shadow_hold",
        read_only: true,
        send_capability: false,
        worker_ready: hold_reasons.is_empty(),
        sender_identity_pinned: expected_sender_sha256.is_some(),
        storage_free_bytes,
        storage_free_basis_points,
        hold_reasons,
        worker_sender_health,
        required_oauth_scopes: [
            "https://www.googleapis.com/auth/gmail.settings.basic",
            "https://www.googleapis.com/auth/drive.metadata.readonly",
        ],
    })
}

async fn get_json(
    client: &reqwest::Client,
    token: &str,
    url: &'static str,
) -> Result<Value, String> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|error| format!("Google audit GET failed: {}", error_chain(&error)))?;
    let status = response.status();
    let body = super::read_body_capped(response, MAX_GOOGLE_RESPONSE_BYTES)
        .await
        .map_err(|error| format!("Google audit GET failed: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "Google audit GET returned {status}; check token scopes and account access"
        ));
    }
    serde_json::from_str(&body)
        .map_err(|error| format!("Google audit GET returned invalid JSON: {error}"))
}

fn token_from_env() -> Result<String, String> {
    let token = std::env::var(TOKEN_ENV).map_err(|_| {
        format!(
            "{TOKEN_ENV} is not set. Supply a dedicated OAuth bearer with Gmail settings.basic              and Drive metadata.readonly scopes; the token is never returned or logged."
        )
    })?;
    if token.trim().is_empty() {
        return Err(format!("{TOKEN_ENV} is empty"));
    }
    Ok(token)
}

fn expected_sender_from_env() -> Result<Option<String>, String> {
    match std::env::var(EXPECTED_SENDER_SHA256_ENV) {
        Ok(value) if valid_sha256(value.trim()) => Ok(Some(value.trim().to_string())),
        Ok(_) => Err(format!(
            "{EXPECTED_SENDER_SHA256_ENV} must be a lowercase 64-character SHA-256 digest"
        )),
        Err(_) => Ok(None),
    }
}

pub async fn scan(client: &reqwest::Client) -> Result<GmailShadowReport, String> {
    let token = token_from_env()?;
    let expected_sender = expected_sender_from_env()?;

    let vacation = get_json(client, &token, VACATION_URL).await?;
    let send_as = get_json(client, &token, SEND_AS_URL).await?;
    let drive_about = get_json(client, &token, DRIVE_ABOUT_URL).await?;
    let observed_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())?
        .as_secs()
        .try_into()
        .map_err(|_| "system clock exceeds supported timestamp range".to_string())?;

    summarize(
        &vacation,
        &send_as,
        &drive_about,
        observed_at_unix_seconds,
        expected_sender.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_793_000_000;

    fn healthy_vacation() -> Value {
        json!({"enableAutoReply": false})
    }

    fn send_as(email: &str, reply_to: Option<&str>, verification: &str) -> Value {
        let mut entry = json!({
            "sendAsEmail": email,
            "isPrimary": true,
            "isDefault": true,
            "verificationStatus": verification
        });
        if let Some(reply_to) = reply_to {
            entry["replyToAddress"] = Value::String(reply_to.to_string());
        }
        json!({"sendAs": [entry]})
    }

    fn safe_quota() -> Value {
        json!({
            "storageQuota": {
                "usage": (8_u64 * 1024 * 1024 * 1024).to_string(),
                "limit": (17_u64 * 1024 * 1024 * 1024).to_string()
            }
        })
    }

    #[test]
    fn healthy_google_settings_are_hash_only_but_still_hold_for_sender_auth() {
        let expected = sha256_hex(b"sender@example.com");
        let report = summarize(
            &healthy_vacation(),
            &send_as("Sender@Example.com", None, "accepted"),
            &safe_quota(),
            NOW,
            Some(&expected),
        )
        .expect("report");

        assert_eq!(report.worker_sender_health.sender_identity_sha256, expected);
        assert_eq!(
            report.worker_sender_health.vacation_responder_disabled,
            AssuranceState::Verified
        );
        assert_eq!(
            report.worker_sender_health.reply_routing,
            AssuranceState::Verified
        );
        assert!(report.storage_free_bytes.is_some_and(|value| value > 0));
        assert!(!report.worker_ready);
        assert_eq!(
            report.hold_reasons,
            vec!["sender_auth_not_proven_by_gmail_api"]
        );

        let encoded = serde_json::to_string(&report).expect("serialize");
        assert!(!encoded.contains("sender@example.com"));
        assert!(!encoded.contains("Sender@Example.com"));
        assert!(!encoded.contains("token"));
    }

    #[test]
    fn enabled_vacation_responder_holds() {
        let expected = sha256_hex(b"sender@example.com");
        let report = summarize(
            &json!({"enableAutoReply": true}),
            &send_as("sender@example.com", None, "accepted"),
            &safe_quota(),
            NOW,
            Some(&expected),
        )
        .expect("report");

        assert!(report.hold_reasons.contains(&"vacation_responder_enabled"));
    }

    #[test]
    fn full_or_missing_storage_holds() {
        let expected = sha256_hex(b"sender@example.com");
        let full = summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "accepted"),
            &json!({"storageQuota": {"usage": "17000000000", "limit": "17000000000"}}),
            NOW,
            Some(&expected),
        )
        .expect("full");
        assert!(full.hold_reasons.contains(&"storage_quota_unsafe"));

        let missing = summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "accepted"),
            &json!({"storageQuota": {}}),
            NOW,
            Some(&expected),
        )
        .expect("missing");
        assert!(missing.hold_reasons.contains(&"storage_quota_unknown"));
    }

    #[test]
    fn unverified_alias_or_external_reply_to_fails_routing() {
        let expected = sha256_hex(b"sender@example.com");
        let unverified = summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "pending"),
            &safe_quota(),
            NOW,
            Some(&expected),
        )
        .expect("unverified");
        assert!(unverified
            .hold_reasons
            .contains(&"reply_routing_unverified"));

        let external_reply = summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", Some("other@example.net"), "accepted"),
            &safe_quota(),
            NOW,
            Some(&expected),
        )
        .expect("external reply");
        assert!(external_reply
            .hold_reasons
            .contains(&"reply_routing_unverified"));
    }

    #[test]
    fn expected_sender_must_match_a_configured_send_as_identity() {
        let wrong = sha256_hex(b"other@example.com");
        let error = summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "accepted"),
            &safe_quota(),
            NOW,
            Some(&wrong),
        )
        .expect_err("wrong sender must fail closed");
        assert!(error.contains("configured sender identity"));
        assert!(!error.contains("sender@example.com"));
    }

    #[test]
    fn missing_expected_sender_pin_keeps_shadow_hold() {
        let report = summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "accepted"),
            &safe_quota(),
            NOW,
            None,
        )
        .expect("report");
        assert!(report
            .hold_reasons
            .contains(&"expected_sender_identity_unpinned"));
        assert!(!report.sender_identity_pinned);
    }

    #[test]
    fn malformed_inputs_fail_closed_without_raw_identity_output() {
        assert!(summarize(
            &healthy_vacation(),
            &json!({"sendAs": []}),
            &safe_quota(),
            NOW,
            None,
        )
        .is_err());
        assert!(summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "accepted"),
            &safe_quota(),
            0,
            None,
        )
        .is_err());
        assert!(summarize(
            &healthy_vacation(),
            &send_as("sender@example.com", None, "accepted"),
            &safe_quota(),
            NOW,
            Some("not-a-digest"),
        )
        .is_err());
    }
}
