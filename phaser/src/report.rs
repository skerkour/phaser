use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {}

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
