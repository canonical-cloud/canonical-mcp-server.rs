//! Hermetic (localhost-only) regression tests for the network hardening in
//! `CanonicalMcp`: bearer-token requests must not follow HTTP redirects, so a
//! hijacked or open redirect can never replay the `Authorization` header to an
//! attacker-chosen host.
//!
//! These construct a `reqwest` client with the same redirect policy the server
//! applies to its token-bearing clients (`server.rs`) and prove the behavior
//! against two throwaway loopback listeners. No external network is touched.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

/// A `reqwest` client configured exactly like the server's `api_http`: a short
/// timeout and a refusal to follow redirects.
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client builds")
}

#[tokio::test]
async fn no_redirect_client_does_not_replay_bearer_token_across_a_redirect() {
    // Upstream B — the redirect *target*. A client that followed the redirect
    // would connect here and replay the token. It is bound but never expected
    // to be contacted; non-blocking so the final assertion cannot hang.
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    target.set_nonblocking(true).expect("target non-blocking");
    let target_port = target.local_addr().expect("target addr").port();

    // Upstream A — replies `302 Found` pointing at B, then closes.
    let redirector = TcpListener::bind("127.0.0.1:0").expect("bind redirector");
    let redirector_port = redirector.local_addr().expect("redirector addr").port();

    let (tx, rx) = mpsc::channel::<String>();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = redirector.accept().expect("accept redirector conn");
        let mut buf = [0u8; 4096];
        let read = stream.read(&mut buf).unwrap_or(0);
        let _ = tx.send(String::from_utf8_lossy(&buf[..read]).into_owned());
        let response = format!(
            "HTTP/1.1 302 Found\r\n\
             Location: http://127.0.0.1:{target_port}/stolen\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });

    let response = no_redirect_client()
        .get(format!("http://127.0.0.1:{redirector_port}/"))
        .bearer_auth("super-secret-token")
        .send()
        .await
        .expect("request to redirector completes");

    // The redirect is surfaced as the final response, not silently followed.
    assert_eq!(
        response.status().as_u16(),
        302,
        "no-redirect client must return the 3xx instead of following it"
    );

    server.join().expect("redirector thread joins");

    // The token was sent to the intended host A (sanity)...
    let request_to_a = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("redirector recorded the request");
    assert!(
        request_to_a
            .to_ascii_lowercase()
            .contains("authorization: bearer super-secret-token"),
        "the bearer token should reach the intended host"
    );

    // ...and B, the redirect target, was never contacted, so the token could
    // not have been replayed to it. A regression to a redirect-following
    // policy would leave a queued connection here.
    match target.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("redirect target was contacted; bearer token may have been replayed"),
        Err(error) => panic!("unexpected accept error on redirect target: {error}"),
    }
}
