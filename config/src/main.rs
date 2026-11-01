use pathward_config::ParsedConfig;
use std::{env, fs::File, process::ExitCode};

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("pathward-config check FILE\npathward-config resolve FILE HOST RAW_URL_PATH");
        return Ok(());
    }
    let valid =
        (args.len() == 2 && args[0] == "check") || (args.len() == 4 && args[0] == "resolve");
    if !valid {
        return Err("usage: pathward-config check FILE | resolve FILE HOST RAW_URL_PATH".into());
    }
    let file = File::open(&args[1]).map_err(|e| format!("cannot open configuration: {e}"))?;
    let parsed = ParsedConfig::read(file).map_err(|e| e.to_string())?;
    let config = parsed.compile().map_err(|e| e.to_string())?;
    if args[0] == "check" {
        let count: usize = config.sites().iter().map(|s| s.publications().len()).sum();
        println!(
            "OK: {} site(s), {count} publication(s)",
            config.sites().len()
        );
    } else {
        let host = args[2].to_str().ok_or("HOST must be UTF-8")?;
        let path = args[3].to_str().ok_or("RAW_URL_PATH must be UTF-8")?;
        let site = config.site(host).ok_or("denied: unknown host")?;
        let target = site
            .resolve(path.as_bytes())
            .ok_or("denied: URL is not published")?;
        println!("root: {}\nfile: {target}", site.root().unwrap_or(""));
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
