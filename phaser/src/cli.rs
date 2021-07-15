use crate::profile::Profile;
use crate::report::OutputFormat;
use crate::Scanner;
use crate::{modules, Error};

pub fn modules() {
    let http_modules = modules::all_http_modules();
    let subdomains_modules = modules::all_subdomains_modules();

    println!("Subdomains modules");
    for module in subdomains_modules {
        println!("    {}: {}", module.name(), module.description());
    }

    println!("HTTP modules");
    for module in http_modules {
        println!("    {}: {}", module.name(), module.description());
    }
}

pub async fn scan(
    target: &str,
    aggressive: bool,
    output_format: OutputFormat,
) -> Result<(), Error> {
    log::info!("Scanning: {}", target);

    let scanner = Scanner::new();

    let profile = if aggressive {
        Profile::aggressive()
    } else {
        Profile::default()
    };

    log::info!("Using {} profile", &profile.name);

    let report = scanner.scan(target, profile).await?;

    match output_format {
        OutputFormat::Text => {
            println!("{:?}", report);
        }
        OutputFormat::Json => {
            let output = serde_json::to_string(&report)?;
            println!("{}", output);
        }
    }

    Ok(())
}
