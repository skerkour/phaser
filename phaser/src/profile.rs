use crate::modules::{all_http_modules, all_subdomains_modules, ModuleName};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub subdomains: bool,
    pub aggressive_modules: bool,
    pub modules: Vec<ModuleName>,
}

impl Default for Profile {
    fn default() -> Self {
        let mut modules: Vec<ModuleName> = all_subdomains_modules()
            .into_iter()
            .filter(|module| !module.is_aggressive())
            .map(|module| module.name())
            .collect();
        let mut http_modules: Vec<ModuleName> = all_http_modules()
            .into_iter()
            .filter(|module| !module.is_aggressive())
            .map(|module| module.name())
            .collect();

        modules.append(&mut http_modules);

        Profile {
            subdomains: true,
            aggressive_modules: false,
            modules,
        }
    }
}

impl Profile {
    pub fn aggressive() -> Self {
        let mut modules: Vec<ModuleName> = all_subdomains_modules()
            .into_iter()
            .map(|module| module.name())
            .collect();
        let mut http_modules: Vec<ModuleName> = all_http_modules()
            .into_iter()
            .map(|module| module.name())
            .collect();

        modules.append(&mut http_modules);

        Profile {
            subdomains: true,
            aggressive_modules: false,
            modules,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfileConfig {
    pub subdomains: Option<bool>,
    pub aggressive_modules: Option<bool>,
    pub modules: Option<Vec<ModuleName>>,
}

// modules:(
// subdomains:[ ]
// tcp: [ ]
// http: [ ]
// )
