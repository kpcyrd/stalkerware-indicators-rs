//! Parse a stalkerware-indicators yaml into a list of [`Rule`](struct.Rule.html)s.
//!
//! ## Example
//!
//! ```
//! use anyhow::Context;
//! use std::fs;
//!
//! fn main() -> anyhow::Result<()> {
//!     let buf = fs::read("test_data/ioc-2022-12-15.yaml")
//!         .context("Failed to read ioc yaml file")?;
//!
//!     let rules = stalkerware_indicators::parse_from_buf(&buf);
//!     for rule in rules {
//!         println!("Rule: {:?}", rule);
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod errors;
mod structs;

use crate::errors::*;
pub use crate::structs::*;
use std::fmt;
use std::fs;
use std::path::Path;

/// Load a yaml ioc.yaml from a byte slice
pub fn parse_from_buf(buf: &[u8]) -> Result<Vec<Rule>> {
    let data =
        serde_yaml::from_slice(buf).context("Failed to parse stalkerware-indicators rules")?;
    Ok(data)
}

/// Load a yaml ioc.yaml from the file system
pub fn parse_from_file<T: AsRef<Path> + fmt::Debug>(path: T) -> Result<Vec<Rule>> {
    let buf = fs::read(&path).with_context(|| anyhow!("Failed to read file: {:?}", path))?;
    parse_from_buf(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_2022_09_14() {
        let rules = parse_from_file("test_data/ioc-2022-09-14.yaml").unwrap();
        assert_eq!(rules.len(), 117);
    }

    #[test]
    fn test_load_2022_12_15() {
        let rules = parse_from_file("test_data/ioc-2022-12-15.yaml").unwrap();
        assert_eq!(rules.len(), 146);
    }

    #[test]
    fn parse_minimal() {
        let buf = r#"
- name: Minimal
  type: stalkerware
        "#;

        let rules = parse_from_buf(buf.as_bytes()).unwrap();
        assert_eq!(
            rules,
            vec![Rule {
                name: "Minimal".to_string(),
                names: Vec::new(),
                r#type: "stalkerware".to_string(),
                packages: Vec::new(),
                distribution: Vec::new(),
                certificates: Vec::new(),
                websites: Vec::new(),
                c2: C2Rule {
                    ips: Vec::new(),
                    domains: Vec::new(),
                },
            },]
        );
    }

    #[test]
    fn parse_empty_c2() {
        let buf = r#"
- name: Minimal
  type: stalkerware
  c2: {}
        "#;

        let rules = parse_from_buf(buf.as_bytes()).unwrap();
        assert_eq!(
            rules,
            vec![Rule {
                name: "Minimal".to_string(),
                names: Vec::new(),
                r#type: "stalkerware".to_string(),
                packages: Vec::new(),
                distribution: Vec::new(),
                certificates: Vec::new(),
                websites: Vec::new(),
                c2: C2Rule {
                    ips: Vec::new(),
                    domains: Vec::new(),
                },
            },]
        );
    }
}
