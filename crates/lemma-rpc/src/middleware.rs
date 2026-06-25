//! RPC middleware: CORS, rate-limit stub, request-id logging.
//!
//! CORS is applied via [`tower_http::cors::CorsLayer`] with permissive defaults
//! for devnet. Production deployments should restrict origins.
//!
//! Rate limiting is a stub — full per-IP rate limiting is deferred to a
//! post-testnet Phase 4 follow-up once load patterns are known.

// CORS is configured in server.rs via CorsLayer::permissive().
// This module is reserved for future middleware (rate limiting, request-id
// tracing, etc.) as the RPC layer matures.
