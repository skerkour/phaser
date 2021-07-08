use crate::{
    modules::{HttpModule, Module, ModuleName, ModuleVersion},
    report::{Finding, ModuleResult, Severity},
    Error,
};
use async_trait::async_trait;
use reqwest::Client;

pub struct GitDirectoryDisclosure {}

impl GitDirectoryDisclosure {
    pub fn new() -> Self {
        GitDirectoryDisclosure {}
    }

    fn is_git_directory_listing(&self, content: &str) -> bool {
        return content.contains("HEAD")
            && content.contains("refs")
            && content.contains("config")
            && content.contains("index")
            && content.contains("objects");
    }
}

impl Module for GitDirectoryDisclosure {
    fn name(&self) -> ModuleName {
        ModuleName::HttpGitDirectoryDisclosure
    }

    fn description(&self) -> String {
        String::from("Check for .git/ directory disclosure")
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
impl HttpModule for GitDirectoryDisclosure {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<Finding>, Error> {
        let url = format!("{}/.git/", &endpoint);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if self.is_git_directory_listing(&body) {
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

#[cfg(test)]
mod tests {
    use super::GitDirectoryDisclosure;

    #[tokio::test]
    async fn is_git_directory() {
        let module = GitDirectoryDisclosure::new();

        let body = r#"COMMIT_EDITMSG
FETCH_HEAD
HEAD
ORIG_HEAD
config
description
hooks
index
info
logs
objects
refs"#;

        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.fr</title> sdsds";

        assert_eq!(true, module.is_git_directory_listing(body));
        assert_eq!(false, module.is_git_directory_listing(body2));
    }
}
