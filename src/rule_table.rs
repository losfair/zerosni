use std::{collections::HashMap, io::Read, net::SocketAddr, path::Path};

use anyhow::{Context, Result, bail};
use compact_str::CompactString;
use serde::Deserialize;
use struson::reader::{JsonReader, JsonStreamReader};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleOverride {
  pub resolver: Option<CompactString>,
  pub direct: Option<SocketAddr>,
  #[serde(default)]
  pub fwmark: u32,
}

#[derive(Debug, Clone)]
pub struct RuleTable {
  exact: HashMap<CompactString, RuleOverride>,
  wildcard: HashMap<CompactString, RuleOverride>,
}

impl RuleTable {
  pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
    let mut file = std::fs::File::open(path.as_ref())
      .with_context(|| format!("unable to open rule table {}", path.as_ref().display()))?;
    Self::from_json_str(&mut file)
  }

  pub fn lookup(&self, hostname: &str) -> Option<RuleOverride> {
    let query = hostname.to_ascii_lowercase();
    if let Some(rule) = self.exact.get(query.as_str()) {
      return Some(rule.clone());
    }
    let mut remainder = query.as_str();
    while let Some(dot_idx) = remainder.find('.') {
      remainder = &remainder[dot_idx + 1..];
      if let Some(rule) = self.wildcard.get(remainder) {
        return Some(rule.clone());
      }
    }
    self.wildcard.get("").cloned()
  }

  fn from_json_str(data: &mut impl Read) -> Result<Self> {
    let mut reader = JsonStreamReader::new(data);
    let mut exact = HashMap::new();
    let mut wildcard = HashMap::new();

    reader.begin_object()?;

    while reader.has_next()? {
      let pattern = reader.next_name_owned()?;
      let overrides: RuleOverride = reader.deserialize_next()?;
      let trimmed = pattern.trim();
      if trimmed.is_empty() {
        bail!("rule table contains an empty pattern");
      }
      validate_overrides(&overrides, trimmed)?;
      if trimmed == "*" {
        insert_unique(&mut wildcard, String::new(), overrides, trimmed)?;
        continue;
      }
      if let Some(rest) = trimmed.strip_prefix("*.") {
        if rest.contains('*') || rest.is_empty() {
          bail!("wildcard rule '{trimmed}' must be '*.<suffix>'");
        }
        insert_unique(&mut wildcard, rest.to_ascii_lowercase(), overrides, trimmed)?;
        continue;
      }
      if trimmed.contains('*') {
        bail!("unsupported wildcard pattern '{trimmed}'");
      }
      insert_unique(&mut exact, trimmed.to_ascii_lowercase(), overrides, trimmed)?;
    }

    reader.end_object()?;

    if exact.is_empty() && wildcard.is_empty() {
      bail!("rule table must define at least one rule");
    }

    Ok(Self { exact, wildcard })
  }
}

fn validate_overrides(overrides: &RuleOverride, pattern: &str) -> Result<()> {
  if overrides.direct.is_some() && overrides.resolver.is_some() {
    bail!("rule '{pattern}' cannot set both 'direct' and 'resolver'");
  }
  Ok(())
}

fn insert_unique(
  map: &mut HashMap<CompactString, RuleOverride>,
  key: String,
  overrides: RuleOverride,
  pattern: &str,
) -> Result<()> {
  if map.contains_key(key.as_str()) {
    bail!("duplicate rule for pattern '{pattern}'");
  }
  map.insert(key.into(), overrides);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn parse_table(src: &str) -> Result<RuleTable> {
    let mut cursor = std::io::Cursor::new(src.as_bytes());
    RuleTable::from_json_str(&mut cursor)
  }

  fn table(src: &str) -> RuleTable {
    parse_table(src).expect("valid table")
  }

  #[test]
  fn matches_first_rule() {
    let table = table(
      r#"{
        "www.example.com": { "fwmark": 1 },
        "*.example.com": { "fwmark": 2 },
        "*": { "fwmark": 3 }
      }"#,
    );
    assert_eq!(table.lookup("www.example.com").unwrap().fwmark, 1);
    assert_eq!(table.lookup("api.example.com").unwrap().fwmark, 2);
    assert_eq!(table.lookup("notexample.com").unwrap().fwmark, 3);
    assert_eq!(table.lookup("other.test").unwrap().fwmark, 3);
  }

  #[test]
  fn resolver_override_respects_case_insensitive_match() {
    let table = table(r#"{ "EXAMPLE.COM": { "resolver": "udp://9.9.9.9" } }"#);
    let rule = table.lookup("Example.com").expect("match");
    assert_eq!(rule.resolver.as_deref(), Some("udp://9.9.9.9"));
    assert_eq!(rule.direct, None);
    assert_eq!(rule.fwmark, 0);
  }

  #[test]
  fn direct_override_parses_address() {
    let table = table(r#"{ "*.example.com": { "direct": "10.0.0.1:8443" } }"#);
    let rule = table.lookup("www.example.com").expect("match");
    assert_eq!(rule.direct, Some("10.0.0.1:8443".parse().unwrap()));
    assert_eq!(rule.resolver, None);
    assert_eq!(rule.fwmark, 0);
  }

  #[test]
  fn rejects_empty_table() {
    let err = parse_table("{}").unwrap_err();
    assert!(err.to_string().contains("must define at least one rule"));
  }

  #[test]
  fn rejects_direct_and_resolver() {
    let err = parse_table(
      r#"{ "www.example.com": { "direct": "10.0.0.1:8443", "resolver": "udp://1.1.1.1" } }"#,
    )
    .unwrap_err();
    assert!(
      err
        .to_string()
        .contains("cannot set both 'direct' and 'resolver'")
    );
  }

  #[test]
  fn wildcard_suffix_and_catch_all() {
    let table = table(
      r#"{
        "*.example.com": { "fwmark": 9 },
        "*": { "fwmark": 4 }
      }"#,
    );
    assert_eq!(table.lookup("a.example.com").unwrap().fwmark, 9);
    assert_eq!(table.lookup("b.c.example.com").unwrap().fwmark, 9);
    assert_eq!(table.lookup("elsewhere.com").unwrap().fwmark, 4);
  }

  #[test]
  fn rejects_complex_wildcards() {
    let err = parse_table(r#"{ "api.*.example.*": { "fwmark": 5 } }"#).unwrap_err();
    assert!(err.to_string().contains("unsupported wildcard pattern"));
  }
}
