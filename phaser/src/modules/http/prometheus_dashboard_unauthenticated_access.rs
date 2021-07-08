use crate::{
    modules::{HttpModule, Module, ModuleName, ModuleVersion},
    report::{Finding, ModuleResult, Severity},
    Error,
};
use async_trait::async_trait;
use reqwest::Client;

pub struct PrometheusDashboardUnauthenticatedAccess {}

impl PrometheusDashboardUnauthenticatedAccess {
    pub fn new() -> Self {
        PrometheusDashboardUnauthenticatedAccess {}
    }
}

impl Module for PrometheusDashboardUnauthenticatedAccess {
    fn name(&self) -> ModuleName {
        ModuleName::HttpPrometheusDashboardUnauthenticatedAccess
    }

    fn description(&self) -> String {
        String::from("Check for Prometheus Dashboard Unauthenticated Access")
    }

    fn version(&self) -> ModuleVersion {
        ModuleVersion(1, 0, 0)
    }

    fn is_aggressive(&self) -> bool {
        false
    }

    fn severity(&self) -> Severity {
        Severity::High
    }
}

#[async_trait]
impl HttpModule for PrometheusDashboardUnauthenticatedAccess {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<Finding>, Error> {
        let url = format!("{}", &endpoint);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body
            .contains(r#"<title>Prometheus Time Series Collection and Processing Server</title>"#)
        {
            return Ok(Some(Finding {
                module: self.name(),
                module_version: self.version(),
                severity: self.severity(),
                result: ModuleResult::Url(url),
            }));
        }

        Ok(None)
    }
}
