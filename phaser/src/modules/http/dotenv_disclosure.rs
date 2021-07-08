use crate::{
    modules::{HttpFinding, HttpModule, Module, ModuleName, ModuleVersion},
    Error,
};
use async_trait::async_trait;
use reqwest::Client;

pub struct DotEnvDisclosure {}

impl DotEnvDisclosure {
    pub fn new() -> Self {
        DotEnvDisclosure {}
    }
}

impl Module for DotEnvDisclosure {
    fn name(&self) -> ModuleName {
        ModuleName::HttpDotenvDisclosure
    }

    fn description(&self) -> String {
        String::from("Check if a .env file disclosure")
    }

    fn version(&self) -> ModuleVersion {
        ModuleVersion(1, 0, 0)
    }

    fn is_aggressive(&self) -> bool {
        false
    }
}

#[async_trait]
impl HttpModule for DotEnvDisclosure {
    async fn scan(
        &self,
        http_client: &Client,
        endpoint: &str,
    ) -> Result<Option<HttpFinding>, Error> {
        let url = format!("{}/.env", &endpoint);
        let res = http_client.get(&url).send().await?;

        if res.status().is_success() {
            return Ok(Some(HttpFinding::DotEnvFileDisclosure(url)));
        }

        Ok(None)
    }
}
