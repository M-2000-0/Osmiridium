use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

mod commands;
mod config;

/// Log output format.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum LogFormat {
    /// Human-readable text (default)
    #[default]
    Text,
    /// One JSON object per line for log shippers
    Json,
}

impl LogFormat {
    fn from_env() -> Option<Self> {
        match std::env::var("OSMOSMPC_LOG_FORMAT")
            .ok()?
            .to_lowercase()
            .as_str()
        {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}

#[derive(Parser)]
#[command(name = "osmiridium", version, about = "SMPC platform for secure multi-party computation", long_about = None)]
struct Cli {
    /// Log output format (overrides OSMOSMPC_LOG_FORMAT)
    #[arg(long, value_enum)]
    log_format: Option<LogFormat>,

    /// Config file path (TOML). Also via OSMOSMPC_CONFIG env var.
    #[arg(long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a test SPDZ computation
    Test {
        /// Number of parties
        #[arg(short, long, default_value_t = 3)]
        parties: usize,
    },
    /// Create a new SMPC session
    CreateSession {
        /// Session name
        #[arg(short, long)]
        name: String,
        /// Circuit file path (JSON)
        #[arg(short, long)]
        circuit: String,
    },
    /// Execute a session
    Execute {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
    /// Generate key shares
    Keygen {
        /// Number of parties
        #[arg(short, long, default_value_t = 3)]
        parties: usize,
    },
    /// Run the API server (REST + gRPC) with optional TLS
    Verify {
        /// Listen address
        #[arg(short, long, default_value = "0.0.0.0")]
        addr: String,
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        /// gRPC listen port (0 disables the gRPC server)
        #[arg(short = 'g', long, default_value_t = 50051)]
        grpc_port: u16,
        /// TLS certificate path (enables TLS when set; also via OSMOSMPC_TLS_CERT or OSMOSMPC_TLS_ENABLED+OSMOSMPC_CERT_DIR)
        #[arg(long)]
        tls_cert: Option<String>,
        /// TLS private key path (also via OSMOSMPC_TLS_KEY)
        #[arg(long)]
        tls_key: Option<String>,
        /// TLS CA certificate path for client verification (also via OSMOSMPC_TLS_CA)
        #[arg(long)]
        tls_ca: Option<String>,
    },
    /// Run a benchmark
    Bench {
        /// Circuit size
        #[arg(short, long, default_value_t = 10)]
        size: usize,
        /// Number of repetitions
        #[arg(short, long, default_value_t = 100)]
        repeats: usize,
    },
    /// Show configuration
    Config,
}

/// Log panic details through tracing and stderr before panic=abort kills the
/// process. Install this as the first thing in main so no context is lost.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| l.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let message = panic_payload_message(info);
        tracing::error!(
            target: "panic",
            location = %location,
            message = %message,
            "process panicked"
        );
        eprintln!("panic at {location}: {message}");
    }));
}

fn panic_payload_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn init_tracing(cli_format: Option<LogFormat>) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("osmiridium=info"));

    let format = cli_format.or_else(LogFormat::from_env).unwrap_or_default();
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let result = match format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Text => builder.try_init(),
    };
    let _ = result;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    install_panic_hook();
    init_tracing(cli.log_format);

    match cli.command {
        Commands::Test { parties } => {
            commands::test_command(parties).await?;
        }
        Commands::CreateSession { name, circuit } => {
            commands::create_session(&name, &circuit).await?;
        }
        Commands::Execute { session } => {
            commands::execute_session(&session).await?;
        }
        Commands::Keygen { parties } => {
            commands::keygen(parties)?;
        }
        Commands::Verify {
            addr,
            port,
            grpc_port,
            tls_cert,
            tls_key,
            tls_ca,
        } => {
            commands::verify(&addr, port, grpc_port, tls_cert, tls_key, tls_ca).await?;
        }
        Commands::Bench { size, repeats } => {
            commands::bench(size, repeats).await?;
        }
        Commands::Config => {
            let config = config::Config::from_env_with_file(cli.config.as_deref());
            println!(
                "Listen: {}:{}\nParties: {}\nParty ID: {}\nTLS: {}\nSecurity bits: {}\nMax rounds: {}\nMalicious: {}\nAPI: {} @ {}:{}\nConfig file: {}\n",
                config.network.listen_addr,
                config.network.listen_port,
                config.network.num_parties,
                config.network.party_id,
                config.network.tls_enabled,
                config.protocol.security_bits,
                config.protocol.max_rounds,
                config.protocol.malicious,
                if config.api.enabled { "enabled" } else { "disabled" },
                config.api.listen_addr,
                config.api.listen_port,
                cli.config.as_deref().unwrap_or("(auto)")
            );
        }
    }

    Ok(())
}
