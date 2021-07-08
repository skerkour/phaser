use anyhow::Result;
use clap::{App, Arg, SubCommand};
use std::env;

mod cli;
mod dns;
mod error;
mod modules;
mod ports;
mod profile;
mod report;
mod scanner;
pub use error::Error;
pub use report::Report;
pub use scanner::Scanner;

use crate::report::OutputFormat;

fn main() -> Result<()> {
    let cli = App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .arg(
            Arg::with_name("debug")
                .help("Display debug logs")
                .long("debug"),
        )
        .subcommand(SubCommand::with_name("modules").about("List all modules"))
        .subcommand(
            SubCommand::with_name("scan")
                .about("Scan a target")
                .arg(
                    Arg::with_name("target")
                        .help("The domain name to scan")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("aggressive")
                        .help("Use aggressive modules")
                        .long("aggressive")
                        .short("a"),
                )
                .arg(
                    Arg::with_name("output")
                        .help("Out pur format. Valid value are [text, json]")
                        .long("output")
                        .short("o")
                        .default_value("text"),
                ),
        )
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .setting(clap::AppSettings::VersionlessSubcommands)
        .get_matches();

    if cli.is_present("debug") {
        env::set_var("RUST_LOG", "debug");
    } else {
        env::set_var("RUST_LOG", "info,trust_dns_proto=error");
    }
    env_logger::init();

    if let Some(_) = cli.subcommand_matches("modules") {
        cli::modules();
    } else if let Some(matches) = cli.subcommand_matches("scan") {
        // we can safely unwrap as the argument is required
        let target = matches.value_of("target").unwrap();
        let aggressive = matches.is_present("aggressive");
        let output = matches.value_of("output").unwrap().to_lowercase();
        let output_format = match output.as_str() {
            "text" => OutputFormat::Text,
            "json" => OutputFormat::Json,
            _ => return Err(Error::InvalidOutputFormat(output).into()),
        };
        cli::scan(target, aggressive, output_format)?;
    }

    Ok(())
}
