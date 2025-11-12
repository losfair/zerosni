use std::{collections::HashMap, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use struson::reader::{JsonReader, JsonStreamReader};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleOverride {
  pub resolver: Option<String>,
  pub fwmark: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RuleTable {
  exact: HashMap<String, RuleOverride>,
  wildcard: HashMap<String, RuleOverride>,
}

impl RuleTable {
  pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
    let mut file = std::fs::File::open(path.as_ref())
      .with_context(|| format!("unable to open rule table {}", path.as_ref().display()))?;
    Self::from_json_str(&mut file)
  }

  pub fn lookup(&self, hostname: &str) -> Option<RuleOverride> {
    let query = hostname.to_ascii_lowercase();
    if let Some(rule) = self.exact.get(&query) {
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
      if overrides.resolver.is_none() && overrides.fwmark.is_none() {
        bail!("rule '{trimmed}' must specify at least one override");
      }
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

    Ok(Self { exact, wildcard })
  }
}

fn insert_unique(
  map: &mut HashMap<String, RuleOverride>,
  key: String,
  overrides: RuleOverride,
  pattern: &str,
) -> Result<()> {
  if map.contains_key(&key) {
    bail!("duplicate rule for pattern '{pattern}'");
  }
  map.insert(key, overrides);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn table(src: &str) -> RuleTable {
    RuleTable::from_json_str(src).expect("valid table")
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
    assert_eq!(table.lookup("www.example.com").unwrap().fwmark, Some(1));
    assert_eq!(table.lookup("api.example.com").unwrap().fwmark, Some(2));
    assert_eq!(table.lookup("notexample.com").unwrap().fwmark, Some(3));
    assert_eq!(table.lookup("other.test").unwrap().fwmark, Some(3));
  }

  #[test]
  fn resolver_override_respects_case_insensitive_match() {
    let table = table(r#"{ "EXAMPLE.COM": { "resolver": "https://9.9.9.9" } }"#);
    let rule = table.lookup("Example.com").expect("match");
    assert_eq!(rule.resolver.as_deref(), Some("https://9.9.9.9"));
    assert_eq!(rule.fwmark, None);
  }

  #[test]
  fn rejects_empty_table() {
    let err = RuleTable::from_json_str("{}").unwrap_err();
    assert!(err.to_string().contains("must define at least one rule"));
  }

  #[test]
  fn rejects_empty_override() {
    let err = RuleTable::from_json_str(r#"{ "*": { } }"#).unwrap_err();
    assert!(
      err
        .to_string()
        .contains("must specify at least one override")
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
    assert_eq!(table.lookup("a.example.com").unwrap().fwmark, Some(9));
    assert_eq!(table.lookup("b.c.example.com").unwrap().fwmark, Some(9));
    assert_eq!(table.lookup("elsewhere.com").unwrap().fwmark, Some(4));
  }

  #[test]
  fn rejects_complex_wildcards() {
    let err = RuleTable::from_json_str(r#"{ "api.*.example.*": { "fwmark": 5 } }"#).unwrap_err();
    assert!(err.to_string().contains("unsupported wildcard pattern"));
  }
}
