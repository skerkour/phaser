use crate::profile::Profile;
use crate::Scanner;
use crate::{modules, Error};

pub fn modules() {
    let http_modules = modules::all_http_modules();
    let subdomains_modules = modules::all_subdomains_modules();

    println!("Subdomains modules");
    for module in subdomains_modules {
        println!("   {}: {}", module.name(), module.description());
    }

    println!("HTTP modules");
    for module in http_modules {
        println!("    {}: {}", module.name(), module.description());
    }
}

pub fn scan(target: &str, aggressive: bool) -> Result<(), Error> {
    log::info!("Scanning: {}", target);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Building tokio's runtime");

    let scanner = Scanner::new();

    let profile = if aggressive {
        log::info!("Using aggressive profile");
        Profile::aggressive()
    } else {
        log::info!("Using default profile");
        Profile::default()
    };

    let report = runtime.block_on(async move { scanner.scan(target, profile).await })?;

    println!("{:?}", report);

    Ok(())
}
