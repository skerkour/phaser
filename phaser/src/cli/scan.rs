use crate::profile::Profile;
use crate::report::OutputFormat;
use crate::Error;
use crate::Scanner;

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
