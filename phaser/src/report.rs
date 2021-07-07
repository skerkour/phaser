use crate::profile::Profile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {
    pub target: String,
    pub profile: Profile,
}

// scan result {
//     profile: {...}
//     target: ""
//     hosts: [
//     {
//     domain: "",
//     resolves: bool,
//     findings: {
//     module: "",
//     finding: { (enum(url,...) }
//     }
//     ]
//     }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Port {
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Eq, PartialEq, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Http,
    Https,
    // Ssh,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Finding {
    Url(String),
}
