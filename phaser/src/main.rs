#![deny(non_ascii_idents)]

use crate::report::OutputFormat;
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
mod tools;

pub use error::Error;
pub use report::Report;
pub use scanner::Scanner;

// Since Rust no longer uses jemalloc by default, phaser will, by default,
// use the system allocator. On Linux, this would normally be glibc's
// allocator, which is pretty good. In particular, phaser does not have a
// particularly allocation heavy workload, so there really isn't much
// difference (for phaser's purposes) between glibc's allocator and jemalloc.
//
// However, when phaser is built with musl, this means phaser will use musl's
// allocator, which appears to be substantially worse. (musl's goal is not to
// have the fastest version of everything. Its goal is to be small and amenable
// to static compilation.) Therefore,
// when building with musl, we use jemalloc.
//
// We don't unconditionally use jemalloc because it can be nice to use the
// system's default allocator by default. Moreover, jemalloc seems to increase
// compilation times by a bit.
//
// Moreover, we only do this on 64-bit systems since jemalloc doesn't support
// i686.
#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
                        .help("Use aggressive modules (disabled by default)")
                        .long("aggressive")
                        .short("a"),
                )
                .arg(
                    Arg::with_name("output")
                        .help("Output format. Valid value are [text, json]")
                        .long("output")
                        .short("o")
                        .default_value("text"),
                ),
        )
        .subcommand(
            SubCommand::with_name("tools")
                .about("Tools to help your offensive operations")
                .subcommand(
                    SubCommand::with_name("dnsquat")
                        .about("Generates permutation for DNS squatting a given domain")
                        .arg(
                            Arg::with_name("domain")
                                .help("The domain name (eg: target)")
                                .required(true)
                                .index(1),
                        )
                        .arg(
                            Arg::with_name("tld")
                                .help("The tld (eg: .com)")
                                .required(true)
                                .index(2),
                        ),
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
        cli::scan(target, aggressive, output_format).await?;
    } else if let Some(tools_matches) = cli.subcommand_matches("tools") {
        if let Some(matches) = tools_matches.subcommand_matches("dnsquat") {
            let domain = matches.value_of("domain").unwrap().to_lowercase();
            let tld = matches.value_of("tld").unwrap().to_lowercase();
            tools::dnsquat(&domain, &tld);
        } else {
            // print all tools
            println!("Tools:");
            println!("    dnsquat: Generates permutation for DNS squatting a given domain");
        }
    }

    Ok(())
}
