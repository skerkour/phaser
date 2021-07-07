use crate::modules::ModuleName;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub subdomains: bool,
    pub aggressive_modules: bool,
    pub modules: Vec<ModuleName>,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            subdomains: true,
            aggressive_modules: true,
            modules: Vec::new(),
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
