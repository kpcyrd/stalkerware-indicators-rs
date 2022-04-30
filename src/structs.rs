use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A rule entry that lists indicators of compromise for a strain of stalkerware
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    /// A canonical name for this strain
    pub name: String,
    /// Other names this stalkerware is known as
    #[serde(default)]
    pub names: Vec<String>,
    /// App identifiers this stalkerware uses
    #[serde(default)]
    pub packages: Vec<String>,
    /// Certificates that are in use with this stalkerware
    #[serde(default)]
    pub certificates: Vec<String>,
    /// Websites that are related to this stalkerware (eg. marketing or panels)
    #[serde(default)]
    pub websites: Vec<String>,
    /// Domains and IP addresses that are used by C2 infrastructure
    #[serde(default)]
    pub c2: C2Rule,
}

/// Struct for C2 infos
#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct C2Rule {
    /// List of known C2 ip addresses
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    /// List of known C2 ip domains
    #[serde(default)]
    pub domains: Vec<String>,
}
