use clap::{error::ErrorKind, Parser};
use std::process::ExitCode;

fn main() -> ExitCode {
    // clap's own usage exit status is 2, which this tool reserves for an
    // unaccepted violation; usage errors are 4 (plan §1).
    let cli = match ext::cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => 4,
            };
            // Nothing sensible remains if printing the usage text fails.
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    ExitCode::from(ext::cli::run(&cli))
}
