use crate::{
    modules::{HttpFinding, HttpModule, Module, ModuleName, ModuleVersion},
    Error,
};
use async_trait::async_trait;
use reqwest::Client;

pub struct GitlabOpenRegistrations {}

impl GitlabOpenRegistrations {
    pub fn new() -> Self {
        GitlabOpenRegistrations {}
    }
}

impl Module for GitlabOpenRegistrations {
    fn name(&self) -> ModuleName {
        ModuleName::HttpGitlabOpenRegistration
    }

    fn description(&self) -> String {
        String::from("Check if the GitLab instance is open to registrations")
    }

    fn version(&self) -> ModuleVersion {
        ModuleVersion(1, 0, 0)
    }

    fn is_aggressive(&self) -> bool {
        false
    }
}

#[async_trait]
impl HttpModule for GitlabOpenRegistrations {
    async fn scan(
        &self,
        http_client: &Client,
        endpoint: &str,
    ) -> Result<Option<HttpFinding>, Error> {
        let url = format!("{}", &endpoint);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body.to_lowercase().contains("ref:") && body.contains("Register") {
            return Ok(Some(HttpFinding::GitlabOpenRegistrations(url)));
        }

        Ok(None)
    }
}
