use clap::Parser;
use sooya::cli::{Cli, CliHandler, Commands};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Commands::Menu);

    match &command {
        Commands::Daemon => {
            CliHandler::run_daemon(&cli.api, cli.data_dir).await?;
        }
        cmd => {
            let handler = CliHandler::new(&cli.api);
            if let Err(e) = handler.run_client_command(cmd, &cli.data_dir).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
