//! gRPC transport module
//!
//! Provides gRPC (HTTP/2) transport for VMess protocol,
//! compatible with v2ray's gRPC transport.

mod codec;
mod connection;
mod heartbeat;
mod transport;

pub use connection::GrpcConnection;
