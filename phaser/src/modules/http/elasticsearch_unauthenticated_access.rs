use crate::{
    modules::{HttpFinding, HttpModule, Module, ModuleName, ModuleVersion},
    Error,
};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct ElasticsearchUnauthenticatedAccess {}

impl ElasticsearchUnauthenticatedAccess {
    pub fn new() -> Self {
        ElasticsearchUnauthenticatedAccess {}
    }
}

impl Module for ElasticsearchUnauthenticatedAccess {
    fn name(&self) -> ModuleName {
        ModuleName::HttpElasticsearchUnauthenticatedAccess
    }

    fn description(&self) -> String {
        String::from("Check for elasticsearch Unauthenticated Access")
    }

    fn version(&self) -> ModuleVersion {
        ModuleVersion(1, 0, 0)
    }

    fn is_aggressive(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ElasticsearchInfo {
    pub name: String,
    pub cluster_name: String,
    pub tagline: String,
}

#[async_trait]
impl HttpModule for ElasticsearchUnauthenticatedAccess {
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

        let info: ElasticsearchInfo = match res.json().await {
            Ok(info) => info,
            Err(_) => return Ok(None), // JSON is not valid, so not an elastisearch server
        };

        if info.tagline.to_lowercase().contains("you know, for search") {
            return Ok(Some(HttpFinding::ElasticsearchUnauthenticatedAccess(url)));
        }

        Ok(None)
    }
}
