//! The `builders` setting: one machine per line (or `;`-separated item),
//! `URI systems ssh-key max-jobs speed-factor features mandatory-features
//! host-key`, where `-` keeps a field's default and `@FILE` includes a
//! machines file.

use std::collections::BTreeSet;

use crate::client::StoreUri;

#[derive(Clone, Debug, PartialEq)]
pub struct Machine {
    pub uri: String,
    pub systems: Vec<String>,
    pub ssh_key: Option<String>,
    pub max_jobs: usize,
    pub speed_factor: f64,
    /// Includes the mandatory features.
    pub supported_features: BTreeSet<String>,
    pub mandatory_features: BTreeSet<String>,
    pub host_key: Option<String>,
}

impl Machine {
    /// Whether this machine may build a derivation for `system` that
    /// requires `features`.
    pub fn can_build(&self, system: &str, features: &BTreeSet<String>) -> bool {
        (self.systems.iter().any(|s| s == system) || system == "builtin")
            && features.is_subset(&self.supported_features)
            && self.mandatory_features.is_subset(features)
    }

    pub fn store_uri(&self) -> Result<StoreUri, String> {
        let mut u = StoreUri::parse(&self.uri).ok_or_else(|| {
            format!("unsupported remote builder URI '{}': only ssh://, ssh-ng://, unix:// and daemon are supported", self.uri)
        })?;
        if let Some(k) = &self.ssh_key {
            u.params.entry("ssh-key".into()).or_insert_with(|| k.clone());
        }
        if let Some(k) = &self.host_key {
            u.params.entry("base64-ssh-public-host-key".into()).or_insert_with(|| k.clone());
        }
        Ok(u)
    }
}

fn field(v: Option<&&str>) -> Option<String> {
    v.filter(|s| !s.is_empty() && **s != "-").map(|s| s.to_string())
}

fn set(v: Option<&&str>) -> BTreeSet<String> {
    field(v).map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default()
}

/// Parses a `builders` value; machines whose system list is `-` build for
/// `local_system`.
pub fn parse(spec: &str, local_system: &str) -> Result<Vec<Machine>, String> {
    let mut out = Vec::new();
    for item in spec.split(['\n', ';']) {
        let item = item.split('#').next().unwrap_or("").trim();
        if item.is_empty() {
            continue;
        }
        if let Some(file) = item.strip_prefix('@') {
            match std::fs::read_to_string(file.trim()) {
                Ok(text) => out.extend(parse(&text, local_system)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("reading machines file '{file}': {e}")),
            }
            continue;
        }
        let t: Vec<&str> = item.split_whitespace().collect();
        let mut uri = t[0].to_string();
        if !uri.contains("://") && uri != "daemon" && uri != "auto" {
            uri = format!("ssh://{uri}");
        }
        let systems = field(t.get(1)).map(|s| s.split(',').map(String::from).collect()).unwrap_or_else(|| vec![local_system.to_string()]);
        let num = |i: usize, what: &str| -> Result<Option<String>, String> {
            let v = field(t.get(i));
            if let Some(s) = &v {
                if s.parse::<f64>().is_err() {
                    return Err(format!("invalid {what} '{s}' for builder '{}'", t[0]));
                }
            }
            Ok(v)
        };
        let max_jobs = num(3, "max jobs")?.map(|s| s.parse::<usize>().map_err(|_| format!("invalid max jobs '{s}'"))).transpose()?.unwrap_or(1);
        let speed_factor = num(4, "speed factor")?.map(|s| s.parse::<f64>().unwrap()).unwrap_or(1.0);
        if speed_factor <= 0.0 {
            return Err(format!("speed factor of builder '{}' must be positive", t[0]));
        }
        let mandatory_features = set(t.get(6));
        let mut supported_features = set(t.get(5));
        supported_features.extend(mandatory_features.iter().cloned());
        out.push(Machine {
            uri,
            systems,
            ssh_key: field(t.get(2)),
            max_jobs,
            speed_factor,
            supported_features,
            mandatory_features,
            host_key: field(t.get(7)),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nix_format() {
        let spec = "ssh-ng://builder@linux x86_64-linux,aarch64-linux /etc/nix/key 4 2 benchmark,big-parallel kvm c3No\n\
                    # comment\n\
                    host2 - - - - - - ; daemon aarch64-darwin";
        let m = parse(spec, "aarch64-darwin").unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].systems, ["x86_64-linux", "aarch64-linux"]);
        assert_eq!(m[0].ssh_key.as_deref(), Some("/etc/nix/key"));
        assert_eq!((m[0].max_jobs, m[0].speed_factor), (4, 2.0));
        assert!(m[0].supported_features.contains("kvm"));
        assert_eq!(m[0].host_key.as_deref(), Some("c3No"));
        assert_eq!(m[1].uri, "ssh://host2");
        assert_eq!(m[1].systems, ["aarch64-darwin"]);
        assert_eq!(m[2].uri, "daemon");

        let none = BTreeSet::new();
        let kvm: BTreeSet<String> = ["kvm".to_string()].into();
        assert!(!m[0].can_build("x86_64-linux", &none), "mandatory feature missing");
        assert!(m[0].can_build("x86_64-linux", &kvm));
        assert!(!m[0].can_build("aarch64-darwin", &kvm));
        assert!(m[1].can_build("aarch64-darwin", &none));
        assert!(!m[1].can_build("aarch64-darwin", &kvm));

        let u = m[0].store_uri().unwrap();
        assert_eq!(u.params["ssh-key"], "/etc/nix/key");
        assert!(m[1].store_uri().is_ok());
        assert!(Machine { uri: "s3://bucket".into(), ..m[1].clone() }.store_uri().is_err());
    }
}
