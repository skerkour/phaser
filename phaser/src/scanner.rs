use crate::dns;
use crate::modules;
use crate::modules::HttpModule;
use crate::modules::Subdomain;
use crate::ports;
use crate::profile::Profile;
use crate::report::ReportV1;
use crate::{Error, Report};
use chrono::Utc;
use futures::stream;
use futures::StreamExt;
use reqwest::Client;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::Duration;

pub struct Scanner {
    http_client: Client,
    dns_resolver: dns::Resolver,
    subdomains_concurrency: usize,
    dns_concurrency: usize,
    vulnerabilities_conccurency: usize,
    ports_concurrency: usize,
}

impl Scanner {
    pub fn new() -> Self {
        let http_timeout = Duration::from_secs(10);
        let http_client = Client::builder()
            .timeout(http_timeout)
            .build()
            .expect("scanner: Building HTTP client");

        Scanner {
            http_client,
            dns_resolver: dns::new_resolver(),
            subdomains_concurrency: 20,
            dns_concurrency: 100,
            vulnerabilities_conccurency: 20,
            ports_concurrency: 200,
        }
    }

    pub async fn scan(&self, target: &str, profile: Profile) -> Result<Report, Error> {
        let mut report = ReportV1 {
            started_at: Utc::now(),
            completed_at: Utc::now(),
            duration_ms: 0,
            target: String::from(target),
            profile,
            hosts: Vec::new(),
        };

        let subdomains_modules = modules::get_subdomains_modules(&report.profile.modules);

        // 1st step: concurrently scan subdomains
        let mut subdomains: Vec<String> = stream::iter(subdomains_modules.into_iter())
            .map(|module| async move {
                match module.enumerate(target).await {
                    Ok(new_subdomains) => Some(new_subdomains),
                    Err(err) => {
                        log::error!("subdomains/{}: {}", module.name(), err);
                        None
                    }
                }
            })
            .buffer_unordered(self.subdomains_concurrency)
            .filter_map(|domain| async { domain })
            .collect::<Vec<Vec<String>>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        subdomains.push(target.to_string());

        // 2nd step: dedup, clean and convert results
        let subdomains: Vec<Subdomain> = HashSet::<String>::from_iter(subdomains.into_iter())
            .into_iter()
            .filter(|subdomain| subdomain.contains(target))
            .map(|domain| Subdomain {
                domain,
                open_ports: Vec::new(),
            })
            .collect();

        log::info!("Found {} domains", subdomains.len());

        // 3rd step: concurrently filter unresolvable domains
        let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
            .map(|domain| dns::resolves(&self.dns_resolver, domain))
            .buffer_unordered(self.dns_concurrency)
            .filter_map(|domain| async move { domain })
            .collect()
            .await;

        // 4th step: concurrently scan ports
        let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
            .map(|domain| {
                log::info!("Scannig ports for {}", &domain.domain);
                ports::scan_ports(self.ports_concurrency, domain)
            })
            .buffer_unordered(1)
            .collect()
            .await;

        for subdomain in &subdomains {
            println!("{}", subdomain.domain);
            for port in &subdomain.open_ports {
                println!("    {}", port.port);
            }
        }

        println!("---------------------- Vulnerabilities ----------------------");

        // 5th step: concurrently scan vulnerabilities
        let mut targets: Vec<(Box<dyn HttpModule>, String)> = Vec::new();
        for subdomain in subdomains {
            for port in subdomain.open_ports {
                let http_modules = modules::get_http_modules(&report.profile.modules);
                for http_module in http_modules {
                    let target = format!("http://{}:{}", &subdomain.domain, port.port);
                    targets.push((http_module, target));
                }
            }
        }

        stream::iter(targets.into_iter())
            .for_each_concurrent(self.vulnerabilities_conccurency, |(module, target)| {
                let http_client = self.http_client.clone();
                async move {
                    match module.scan(&http_client, &target).await {
                        Ok(Some(finding)) => println!("{:?}", &finding),
                        Ok(None) => {}
                        Err(err) => log::debug!("Error: {}", err),
                    };
                }
            })
            .await;

        report.completed_at = Utc::now();
        let scan_duration = report.completed_at - report.started_at;
        report.duration_ms = scan_duration.num_milliseconds() as u64;

        Ok(Report::V1(report))
    }
}
