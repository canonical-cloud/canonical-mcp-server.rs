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

    #[test]
    fn cap_take_appends_whole_chunk_below_cap() {
        // Room to spare: take the whole chunk, keep reading.
        assert_eq!(cap_take(0, 100, 1024), (100, false));
        assert_eq!(cap_take(500, 100, 1024), (100, false));
    }

    #[test]
    fn cap_take_stops_exactly_at_cap() {
        // Chunk that lands exactly on the cap is fully taken, then stop.
        assert_eq!(cap_take(1000, 24, 1024), (24, true));
    }

    #[test]
    fn cap_take_truncates_overflowing_chunk() {
        // Only the bytes up to the cap are taken; the index is in range.
        assert_eq!(cap_take(1000, 500, 1024), (24, true));
        assert_eq!(cap_take(0, 5000, 1024), (1024, true));
    }

    #[test]
    fn cap_take_saturates_when_already_full() {
        // Never underflows or asks for a negative/oversized slice.
        assert_eq!(cap_take(1024, 100, 1024), (0, true));
        assert_eq!(cap_take(2048, 100, 1024), (0, true));
    }

    #[test]
    fn cap_take_take_never_exceeds_chunk_len() {
        // Invariant relied on by `read_body_capped`'s `&chunk[..take]`.
        for buffered in [0usize, 10, 1000, 1024, 5000] {
            for chunk_len in [0usize, 1, 24, 500, 5000] {
                let (take, _) = cap_take(buffered, chunk_len, 1024);
                assert!(take <= chunk_len, "take {take} > chunk_len {chunk_len}");
            }
        }
    }
}
