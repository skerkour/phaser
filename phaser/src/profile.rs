use crate::modules::ModuleName;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub subdomains: bool,
    pub aggressive_modules: bool,
    pub modules: Vec<ModuleName>,
}

// modules:(
// subdomains:[ ]
// tcp: [ ]
// http: [ ]
// )
