use clap::{error::ErrorKind, Parser};
use std::process::ExitCode;

/// ES-17: variables that would alter routing, name resolution or TLS key
/// logging. They are removed before anything runs, so neither ext nor a
/// library it calls (getaddrinfo, the HTTP client) can act on them.
const IGNORED_ENV: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "RES_OPTIONS",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCALRES",
    "RESOLV_HOST_CONF",
    "RESOLV_MULTI",
    "RESOLV_REORDER",
    "RESOLV_SPOOF_CHECK",
    "RESOLV_ADD_TRIM_DOMAINS",
    "RESOLV_OVERRIDE_TRIM_DOMAINS",
    "SSLKEYLOGFILE",
];

fn main() -> ExitCode {
    for (k, _) in std::env::vars_os() {
        let upper = k.to_string_lossy().to_ascii_uppercase();
        // Proxy variables count in any case.
        if IGNORED_ENV.contains(&upper.as_str()) {
            // Single-threaded here: no other thread can be reading the
            // environment while it changes.
            std::env::remove_var(&k);
        }
    }
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
