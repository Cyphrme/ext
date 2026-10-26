//! Command-line surface (plan §5). Scaffold: parsing only, no behaviour.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ext", version)]
pub struct Cli {
    /// Store (or a directory whose `.ext/` is a store).
    #[arg(long = "d", global = true)]
    pub d: Option<PathBuf>,
    /// Hex (uppercase) instead of b64ut digests in output.
    #[arg(long, global = true)]
    pub hex: bool,
    /// NUL-terminated records with raw paths.
    #[arg(short = '0', global = true)]
    pub nul: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    Init {
        dir: Option<PathBuf>,
        #[arg(long)]
        bare: Option<PathBuf>,
    },
    #[command(short_flag = 'r')]
    Register {
        path: PathBuf,
    },
    #[command(short_flag = 'u')]
    Unregister {
        path: PathBuf,
    },
    Resolve {
        digest: String,
    },
    List,
    Check {
        #[arg(long)]
        full: bool,
        #[arg(long)]
        accept: bool,
    },
    Rebuild,
}
