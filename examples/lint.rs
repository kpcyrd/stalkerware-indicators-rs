use clap::{ArgAction, Parser};
use env_logger::Env;
use stalkerware_indicators::errors::*;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    /// Path to `ioc.yaml` to lint
    file: PathBuf,
    /// Print parsed data as json
    #[clap(long)]
    dump_json: bool,
    /// Verbose output
    #[clap(short, action=ArgAction::Count)]
    verbose: u8,
    /// Quiet output
    #[clap(short)]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match (args.quiet, args.verbose) {
        (true, _) => "warn",
        (_, 1) => "info",
        (_, 2) => "info",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    let rules = stalkerware_indicators::parse_from_file(args.file)?;
    info!("Loadeded {} rules", rules.len());
    if args.dump_json {
        serde_json::to_writer_pretty(io::stdout(), &rules)?;
    }

    let packages = rules
        .iter()
        .flat_map(|r| r.packages.iter().cloned())
        .collect::<HashSet<_>>();
    info!("Stats: {} known packages", packages.len());

    let domains = rules
        .iter()
        .flat_map(|r| r.websites.iter().chain(r.c2.domains.iter()).cloned())
        .collect::<HashSet<_>>();
    info!("Stats: {} known domains", domains.len());

    let ips = rules
        .iter()
        .flat_map(|r| r.c2.ips.iter().cloned())
        .collect::<HashSet<_>>();
    info!("Stats: {} known ips", ips.len());

    Ok(())
}
