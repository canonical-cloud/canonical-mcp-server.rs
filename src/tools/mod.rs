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
/// 4 MiB comfortably covers legitimate API and documentation responses while
/// keeping the process memory bound explicit.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

fn fits_within_limit(buffered: usize, chunk_len: usize, max_bytes: usize) -> bool {
    max_bytes
        .checked_sub(buffered)
        .is_some_and(|remaining| chunk_len <= remaining)
}

fn response_too_large(max_bytes: usize) -> String {
    format!("response body exceeded {max_bytes} byte limit")
}

/// Read an HTTP response body to a `String` while rejecting any response that
/// exceeds `max_bytes`.
///
/// The reader never appends a partial chunk. That distinction matters: silently
/// returning a truncated 2xx document can turn an availability or upstream
/// integrity failure into apparently valid-but-incomplete audit evidence. A
/// response exactly equal to the limit is accepted only after EOF is observed;
/// the next non-empty chunk produces a typed error without being buffered.
/// Content-Length is checked up front when available, and chunked responses are
/// enforced incrementally. UTF-8 decoding remains lossy to match reqwest's
/// previous text behavior without risking a panic at a multibyte boundary.
pub async fn read_body_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(response_too_large(max_bytes));
    }

    let initial_capacity = response
        .content_length()
        .map_or(0, |length| length.min(max_bytes as u64) as usize);
    let mut buffer = Vec::with_capacity(initial_capacity);

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("error reading body: {}", error_chain(&error)))?
    {
        if !fits_within_limit(buffer.len(), chunk.len(), max_bytes) {
            return Err(response_too_large(max_bytes));
        }
        buffer.extend_from_slice(&chunk);
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

    #[test]
    fn limit_accepts_chunks_that_fit_including_the_exact_boundary() {
        assert!(fits_within_limit(0, 100, 1024));
        assert!(fits_within_limit(500, 100, 1024));
        assert!(fits_within_limit(1000, 24, 1024));
        assert!(fits_within_limit(1024, 0, 1024));
    }

    #[test]
    fn limit_rejects_overflow_without_partial_append_arithmetic() {
        assert!(!fits_within_limit(1000, 25, 1024));
        assert!(!fits_within_limit(0, 1025, 1024));
        assert!(!fits_within_limit(1024, 1, 1024));
        assert!(!fits_within_limit(2048, 0, 1024));
    }

    #[test]
    fn oversized_body_error_is_bounded_and_does_not_echo_remote_content() {
        assert_eq!(
            response_too_large(4 * 1024 * 1024),
            "response body exceeded 4194304 byte limit"
        );
    }
}
