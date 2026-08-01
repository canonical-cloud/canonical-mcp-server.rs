pub mod cloudflare;
pub mod docs;
pub mod domain;
pub mod fiducia;
pub mod github;
pub mod health;
pub mod k8s;

/// Render an error with its full source chain, e.g.
/// `error sending request: dns error: failed to lookup address`.
/// `std::fmt::Display` on reqwest errors alone hides the useful cause.
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Hard cap on how many bytes we buffer from any single upstream HTTP
/// response. Every tool hits third-party endpoints (GitHub, Cloudflare,
/// RDAP, DNS-over-HTTPS, fiducia, and operator-supplied deployment URLs); a
/// per-request timeout bounds *time* but not *memory*, so a hostile or
/// misconfigured upstream could otherwise stream unbounded data into RAM.
/// 4 MiB comfortably covers the largest legitimate JSON payloads (a full
/// Cloudflare zone listing, a `kubectl`-scale document) while capping the
/// blast radius.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// How many bytes of the next `chunk_len`-byte chunk may be appended to a
/// buffer already holding `buffered` bytes without exceeding `max_bytes`,
/// and whether that append reaches the cap (i.e. reading should stop).
///
/// Pure and saturating so the streaming reader can never compute an
/// out-of-range slice index. Split out so the boundary arithmetic — the
/// only bug-prone part of capped reading — is unit-testable without a
/// network.
fn cap_take(buffered: usize, chunk_len: usize, max_bytes: usize) -> (usize, bool) {
    let remaining = max_bytes.saturating_sub(buffered);
    if chunk_len >= remaining {
        (remaining, true)
    } else {
        (chunk_len, false)
    }
}

/// Read an HTTP response body to a `String`, buffering at most `max_bytes`
/// and then stopping (the connection is dropped with the response). The
/// body is decoded lossily so a chunk boundary that splits a multibyte
/// UTF-8 sequence yields a replacement character rather than a panic; a
/// truncated body simply fails to parse downstream as a typed error.
pub async fn read_body_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, String> {
    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("error reading body: {}", error_chain(&error)))?
    {
        let (take, capped) = cap_take(buffer.len(), chunk.len(), max_bytes);
        buffer.extend_from_slice(&chunk[..take]);
        if capped {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Outer(std::io::Error);

    impl std::fmt::Display for Outer {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "outer failed")
        }
    }

    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_chain_includes_sources() {
        let error = Outer(std::io::Error::other("inner cause"));
        assert_eq!(error_chain(&error), "outer failed: inner cause");
    }
}
