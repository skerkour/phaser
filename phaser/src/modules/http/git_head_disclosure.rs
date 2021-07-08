use crate::{
    modules::{HttpModule, Module, ModuleName, ModuleVersion},
    report::{Finding, ModuleResult, Severity},
    Error,
};
use async_trait::async_trait;
use reqwest::Client;

pub struct GitHeadDisclosure {}

impl GitHeadDisclosure {
    pub fn new() -> Self {
        GitHeadDisclosure {}
    }

    fn is_head_file(&self, content: &str) -> bool {
        return Some(0) == content.to_lowercase().trim().find("ref:");
    }
}

impl Module for GitHeadDisclosure {
    fn name(&self) -> ModuleName {
        ModuleName::HttpGitHeadDisclosure
    }

    fn description(&self) -> String {
        String::from("Check for .git/HEAD file disclosure")
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
impl HttpModule for GitHeadDisclosure {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<Finding>, Error> {
        let url = format!("{}/.git/HEAD", &endpoint);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if self.is_head_file(&body) {
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
    use super::GitHeadDisclosure;

    #[test]
    fn is_git_head_file() {
        let module = GitHeadDisclosure::new();

        let body = r#"ref: refs/heads/master"#;
        let body2 = r#"ref: refs/heads/heroku"#;
        let body3 = "test test test test  <tle>Index of kerkour.com</title> test";

        assert_eq!(true, module.is_head_file(body));
        assert_eq!(true, module.is_head_file(body2));
        assert_eq!(false, module.is_head_file(body3));
    }
}
