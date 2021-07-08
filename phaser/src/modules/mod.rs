use std::{collections::HashSet, fmt, iter::FromIterator};

use crate::Error;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

mod http;
mod subdomains;

pub fn all_http_modules() -> Vec<Box<dyn HttpModule>> {
    return vec![
        Box::new(http::DsStoreDisclosure::new()),
        Box::new(http::DotEnvDisclosure::new()),
        Box::new(http::DirectoryListingDisclosure::new()),
        Box::new(http::TraefikDashboardUnauthenticatedAccess::new()),
        Box::new(http::PrometheusDashboardUnauthenticatedAccess::new()),
        Box::new(http::KibanaUnauthenticatedAccess::new()),
        Box::new(http::GitlabOpenRegistrations::new()),
        Box::new(http::GitHeadDisclosure::new()),
        Box::new(http::GitDirectoryDisclosure::new()),
        Box::new(http::GitConfigDisclosure::new()),
        Box::new(http::EtcdUnauthenticatedAccess::new()),
        Box::new(http::Cve2017_9506::new()),
        Box::new(http::Cve2018_7600::new()),
        Box::new(http::ElasticsearchUnauthenticatedAccess::new()),
    ];
}

pub fn get_http_modules(modules: &Vec<ModuleName>) -> Vec<Box<dyn HttpModule>> {
    let modules: HashSet<ModuleName> = HashSet::from_iter(modules.iter().cloned());

    all_http_modules()
        .into_iter()
        .filter(|module| modules.contains(&module.name()))
        .collect()
}

pub fn all_subdomains_modules() -> Vec<Box<dyn SubdomainModule>> {
    return vec![
        Box::new(subdomains::Crtsh::new()),
        Box::new(subdomains::WebArchive::new()),
    ];
}

pub fn get_subdomains_modules(modules: &Vec<ModuleName>) -> Vec<Box<dyn SubdomainModule>> {
    let modules: HashSet<ModuleName> = HashSet::from_iter(modules.iter().cloned());

    all_subdomains_modules()
        .into_iter()
        .filter(|module| modules.contains(&module.name()))
        .collect()
}

#[derive(Debug, Clone, Eq, PartialEq, Copy, Deserialize, Serialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ModuleName {
    // Subdomains
    SubdomainsCrtsh,
    SubdomainsWebArchive,

    // Http
    HttpCve2017_9506,
    HttpCve2018_7600,
    HttpDirectoryListingDisclosure,
    HttpDotenvDisclosure,
    HttpDsStoreDisclosure,
    HttpElasticsearchUnauthenticatedAccess,
    HttpEtcdUnauthenticatedAccess,
    HttpGitConfigDisclosure,
    HttpGitDirectoryDisclosure,
    HttpGitHeadDisclosure,
    HttpGitlabOpenRegistration,
    HttpKibanaUnauthenticatedAccess,
    HttpPrometheusDashboardUnauthenticatedAccess,
    HttpTraefikDashboardUnauthenticatedAccess,
}

impl fmt::Display for ModuleName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Subdomains
            ModuleName::SubdomainsCrtsh => write!(f, "subdomains/crtsh"),
            ModuleName::SubdomainsWebArchive => write!(f, "subdomains/web_archive"),

            // Http
            ModuleName::HttpCve2017_9506 => write!(f, "http/cve_2017_9506"),
            ModuleName::HttpCve2018_7600 => write!(f, "http/cve_2018_7600"),
            ModuleName::HttpDirectoryListingDisclosure => {
                write!(f, "http/directory_listing_disclosure")
            }
            ModuleName::HttpDotenvDisclosure => write!(f, "http/dotenv_disclosure"),
            ModuleName::HttpDsStoreDisclosure => write!(f, "http/ds_store_disclosure"),
            ModuleName::HttpElasticsearchUnauthenticatedAccess => {
                write!(f, "http/elasticsearch_unauthenticated_access")
            }
            ModuleName::HttpEtcdUnauthenticatedAccess => {
                write!(f, "http/etcd_unauthenticated_access")
            }
            ModuleName::HttpGitConfigDisclosure => write!(f, "http/git_config_disclosure"),
            ModuleName::HttpGitDirectoryDisclosure => write!(f, "http/git_directory_disclosure"),
            ModuleName::HttpGitHeadDisclosure => write!(f, "http/git_head_disclosure"),
            ModuleName::HttpGitlabOpenRegistration => write!(f, "http/gitlab_open_registration"),
            ModuleName::HttpKibanaUnauthenticatedAccess => {
                write!(f, "http/kibana_unauthenticated_access")
            }
            ModuleName::HttpPrometheusDashboardUnauthenticatedAccess => {
                write!(f, "http/prometheus_dashboard_unauthenticated_access")
            }
            ModuleName::HttpTraefikDashboardUnauthenticatedAccess => {
                write!(f, "http/traefik_dashboard_unauthenticated_access")
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModuleVersion(u8, u8, u8);

impl fmt::Display for ModuleVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

pub trait Module {
    fn name(&self) -> ModuleName;
    fn version(&self) -> ModuleVersion;
    fn description(&self) -> String;
    fn is_aggressive(&self) -> bool;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Subdomains
////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
pub trait SubdomainModule: Module {
    async fn enumerate(&self, domain: &str) -> Result<Vec<String>, Error>;
}

#[derive(Debug, Clone)]
pub struct Subdomain {
    pub domain: String,
    pub open_ports: Vec<Port>,
}

#[derive(Debug, Clone)]
pub struct Port {
    pub port: u16,
    pub is_open: bool,
    pub findings: Vec<HttpFinding>,
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP
////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
pub trait HttpModule: Module {
    async fn scan(
        &self,
        http_client: &Client,
        endpoint: &str,
    ) -> Result<Option<HttpFinding>, Error>;
}

#[derive(Debug, Clone)]
pub enum HttpFinding {
    DsStoreFileDisclosure(String),
    DotEnvFileDisclosure(String),
    DirectoryListingDisclosure(String),
    TraefikDashboardUnauthenticatedAccess(String),
    PrometheusDashboardUnauthenticatedAccess(String),
    KibanaUnauthenticatedAccess(String),
    GitlabOpenRegistrations(String),
    GitHeadDisclosure(String),
    GitDirectoryDisclosure(String),
    GitConfigDisclosure(String),
    EtcdUnauthenticatedAccess(String),
    Cve2017_9506(String),
    Cve2018_7600(String),
    ElasticsearchUnauthenticatedAccess(String),
}
