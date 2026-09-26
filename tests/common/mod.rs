//! Helpers shared by the integration tests.

/// Under `rustls-no-provider` nothing can build a reqwest client until a
/// process-wide CryptoProvider is installed; the tests use ring. A no-op
/// with the other TLS features.
pub fn install_crypto_provider() {
    #[cfg(feature = "rustls-no-provider")]
    let _ = rustls::crypto::ring::default_provider().install_default();
}
