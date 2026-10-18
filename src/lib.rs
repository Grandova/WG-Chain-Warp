pub mod api;
pub mod cli;
pub mod engine;
pub mod error;
pub mod health;
pub mod model;
pub mod network;
pub mod warp_kernel;
pub mod web;
pub mod wireguard;

pub static LOG_FILTER: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<
        tracing_subscriber::filter::Targets,
        tracing_subscriber::Registry,
    >,
> = std::sync::OnceLock::new();

pub fn init_logging() {
    use tracing_subscriber::prelude::*;
    let (filter, handle) = tracing_subscriber::reload::Layer::new(
        tracing_subscriber::filter::Targets::new().with_default(tracing::Level::INFO),
    );
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact(),
        )
        .init();
    LOG_FILTER.set(handle).expect("logging already initialized");
}
