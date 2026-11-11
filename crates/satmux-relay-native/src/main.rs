//! The native relay: `satmux-relay-logic` on tokio. Reads only its environment.

use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match satmux_relay_native::Config::from_lookup(|name| std::env::var(name).ok()) {
        Ok(config) => config,
        Err(reason) => {
            eprintln!("satmux-relay-native: {reason}");
            return ExitCode::from(100);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("satmux-relay-native: runtime: {error}");
            return ExitCode::from(111);
        }
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let listener = match tokio::net::TcpListener::bind(config.listen).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("satmux-relay-native: listen {}: {error}", config.listen);
                return ExitCode::from(111);
            }
        };
        let stop = async {
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                _ = terminate.recv() => Ok::<(), std::io::Error>(()),
                interrupted = tokio::signal::ctrl_c() => interrupted,
            }
        };
        tokio::select! {
            asked = stop => match asked {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("satmux-relay-native: signals: {error}");
                    ExitCode::from(111)
                }
            },
            error = satmux_relay_native::serve(listener, config) => {
                eprintln!("satmux-relay-native: accept: {error}");
                ExitCode::from(111)
            }
        }
    })
}
