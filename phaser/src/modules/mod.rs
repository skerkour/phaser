use std::fmt;

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

pub fn all_subdomains_modules() -> Vec<Box<dyn SubdomainModule>> {
    return vec![
        Box::new(subdomains::Crtsh::new()),
        Box::new(subdomains::WebArchive::new()),
    ];
}

#[derive(Debug, Clone, Eq, PartialEq, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleName {
    // Subdomains
    SubdomainsCrtsh,

    // Http
    HttpGitHeadDisclosure,
}

impl fmt::Display for ModuleName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ModuleName::SubdomainsCrtsh => write!(f, "subdomains/crtsh"),
            ModuleName::HttpGitHeadDisclosure => write!(f, "http/git_head_disclosure"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModuleVersion(String);

impl fmt::Display for ModuleVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Module {
    fn name(&self) -> ModuleName;
    fn version(&self) -> String;
    fn description(&self) -> String;
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
