//! `flake.lock` (versions 5–7), read and written byte-compatibly with Nix.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use cranix_fetchers::attrs;
use serde_json::{json, Value as Json};

use super::flakeref::FlakeRef;

pub type InputPath = Vec<String>;

pub fn print_input_path(p: &[String]) -> String {
    p.join("/")
}

pub fn parse_input_path(s: &str) -> Result<InputPath, String> {
    let mut v = Vec::new();
    for e in s.split('/').filter(|e| !e.is_empty()) {
        if !cranix_fetchers::url::flake_id_regex().is_match(e) {
            return Err(format!("invalid flake input path element '{e}'"));
        }
        v.push(e.to_string());
    }
    Ok(v)
}

#[derive(Clone)]
pub enum Edge {
    Node(Rc<Node>),
    Follows(InputPath),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locked {
    pub locked: FlakeRef,
    pub original: FlakeRef,
    pub is_flake: bool,
}

/// A lock file node: the root (no `locked`) or a locked input.
pub struct Node {
    pub inputs: RefCell<BTreeMap<String, Edge>>,
    pub locked: Option<Locked>,
}

impl Node {
    pub fn root() -> Rc<Node> {
        Rc::new(Node { inputs: RefCell::new(BTreeMap::new()), locked: None })
    }

    pub fn locked(l: Locked) -> Rc<Node> {
        Rc::new(Node { inputs: RefCell::new(BTreeMap::new()), locked: Some(l) })
    }
}

#[derive(Clone)]
pub struct LockFile {
    pub root: Rc<Node>,
}

impl Default for LockFile {
    fn default() -> Self {
        LockFile { root: Node::root() }
    }
}

fn flake_ref_of(j: &Json, attr: &str, info: Option<&str>) -> Result<FlakeRef, String> {
    let v = j.get(attr).ok_or_else(|| format!("attribute '{attr}' missing in lock file"))?;
    let mut a = attrs::from_json(v)?;
    if let Some(info) = info.and_then(|i| j.get(i)) {
        for (k, v) in attrs::from_json(info)? {
            a.insert(k, v);
        }
    }
    FlakeRef::from_attrs(a)
}

impl LockFile {
    pub fn parse(text: &str, path: &str) -> Result<LockFile, String> {
        let j: Json = serde_json::from_str(text).map_err(|e| format!("parsing lock file '{path}': {e}"))?;
        let version = j.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if !(5..=7).contains(&version) {
            return Err(format!("lock file '{path}' has unsupported version {version}"));
        }
        let nodes = j.get("nodes").ok_or("lock file has no 'nodes'")?;
        let root_key = j.get("root").and_then(|r| r.as_str()).ok_or("lock file has no 'root'")?.to_string();
        let root = Node::root();
        let mut map: HashMap<String, Rc<Node>> = HashMap::new();
        map.insert(root_key.clone(), root.clone());
        fn get_inputs(node: &Rc<Node>, jn: &Json, nodes: &Json, map: &mut HashMap<String, Rc<Node>>) -> Result<(), String> {
            let Some(inputs) = jn.get("inputs").and_then(|i| i.as_object()) else { return Ok(()) };
            for (name, v) in inputs {
                if let Some(arr) = v.as_array() {
                    let p = arr.iter().filter_map(|x| x.as_str().map(String::from)).collect();
                    node.inputs.borrow_mut().insert(name.clone(), Edge::Follows(p));
                    continue;
                }
                let key = v.as_str().ok_or("invalid lock file input")?.to_string();
                let child = match map.get(&key) {
                    Some(c) => c.clone(),
                    None => {
                        let jn2 = nodes.get(&key).ok_or_else(|| format!("lock file references missing node '{key}'"))?;
                        let l = Locked {
                            locked: flake_ref_of(jn2, "locked", Some("info"))?,
                            original: flake_ref_of(jn2, "original", None)?,
                            is_flake: jn2.get("flake").and_then(|f| f.as_bool()).unwrap_or(true),
                        };
                        if !l.locked.input.is_locked() {
                            return Err(format!("lock file contains unlocked input '{}'", attrs::to_json_string(&l.locked.input.attrs)));
                        }
                        let c = Node::locked(l);
                        map.insert(key.clone(), c.clone());
                        get_inputs(&c, jn2, nodes, map)?;
                        c
                    }
                };
                if child.locked.is_none() {
                    return Err("lock file contains cycle to root node".into());
                }
                node.inputs.borrow_mut().insert(name.clone(), Edge::Node(child));
            }
            Ok(())
        }
        let jroot = nodes.get(&root_key).ok_or("lock file references missing root node")?;
        get_inputs(&root, jroot, nodes, &mut map)?;
        Ok(LockFile { root })
    }

    /// The JSON form and the key each node got.
    pub fn to_json(&self) -> (Json, Vec<(Rc<Node>, String)>) {
        let mut nodes = serde_json::Map::new();
        let mut keys: BTreeSet<String> = BTreeSet::new();
        let mut node_keys: Vec<(Rc<Node>, String)> = Vec::new();
        fn dump(
            key: &str,
            node: &Rc<Node>,
            nodes: &mut serde_json::Map<String, Json>,
            keys: &mut BTreeSet<String>,
            node_keys: &mut Vec<(Rc<Node>, String)>,
        ) -> String {
            if let Some((_, k)) = node_keys.iter().find(|(n, _)| Rc::ptr_eq(n, node)) {
                return k.clone();
            }
            let mut key = key.to_string();
            if !keys.insert(key.clone()) {
                for n in 2.. {
                    let k = format!("{key}_{n}");
                    if keys.insert(k.clone()) {
                        key = k;
                        break;
                    }
                }
            }
            node_keys.push((node.clone(), key.clone()));
            let mut n = serde_json::Map::new();
            let inputs = node.inputs.borrow().clone();
            if !inputs.is_empty() {
                let mut ij = serde_json::Map::new();
                for (name, e) in &inputs {
                    let v = match e {
                        Edge::Node(c) => Json::String(dump(name, c, nodes, keys, node_keys)),
                        Edge::Follows(p) => Json::Array(p.iter().map(|x| Json::String(x.clone())).collect()),
                    };
                    ij.insert(name.clone(), v);
                }
                n.insert("inputs".into(), Json::Object(ij));
            }
            if let Some(l) = &node.locked {
                n.insert("original".into(), attrs::to_json(&l.original.to_attrs()));
                let mut la = l.locked.to_attrs();
                la.remove("__final");
                n.insert("locked".into(), attrs::to_json(&la));
                if !l.is_flake {
                    n.insert("flake".into(), Json::Bool(false));
                }
            }
            nodes.insert(key.clone(), Json::Object(n));
            key
        }
        let root = dump("root", &self.root, &mut nodes, &mut keys, &mut node_keys);
        (json!({ "nodes": Json::Object(nodes), "root": root, "version": 7 }), node_keys)
    }

    /// The lock file text without the trailing newline Nix adds on write.
    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self.to_json().0).unwrap()
    }

    pub fn find_input(&self, path: &[String]) -> Option<Rc<Node>> {
        let mut visited = Vec::new();
        self.find(path, &mut visited).ok().flatten()
    }

    fn find(&self, path: &[String], visited: &mut Vec<InputPath>) -> Result<Option<Rc<Node>>, String> {
        if let Some(i) = visited.iter().position(|v| v == path) {
            let mut cycle: Vec<String> = visited[i..].iter().map(|p| print_input_path(p)).collect();
            cycle.push(print_input_path(path));
            return Err(format!("follow cycle detected: [{}]", cycle.join(" -> ")));
        }
        visited.push(path.to_vec());
        let mut pos = self.root.clone();
        for elem in path {
            let e = pos.inputs.borrow().get(elem).cloned();
            match e {
                Some(Edge::Node(n)) => pos = n,
                Some(Edge::Follows(f)) => match self.find(&f, visited)? {
                    Some(n) => pos = n,
                    None => return Ok(None),
                },
                None => return Ok(None),
            }
        }
        Ok(Some(pos))
    }

    /// Every node reachable from the root with its shortest input path.
    pub fn all_inputs(&self) -> BTreeMap<InputPath, Edge> {
        let mut res = BTreeMap::new();
        let mut done: Vec<*const Node> = Vec::new();
        fn rec(n: &Rc<Node>, prefix: &InputPath, res: &mut BTreeMap<InputPath, Edge>, done: &mut Vec<*const Node>) {
            if done.contains(&Rc::as_ptr(n)) {
                return;
            }
            done.push(Rc::as_ptr(n));
            for (k, e) in n.inputs.borrow().iter() {
                let mut p = prefix.clone();
                p.push(k.clone());
                res.insert(p.clone(), e.clone());
                if let Edge::Node(c) = e {
                    rec(c, &p, res, done);
                }
            }
        }
        rec(&self.root, &Vec::new(), &mut res, &mut done);
        res
    }

    /// Fails if a `follows` points at an input that does not exist.
    pub fn check(&self) -> Result<(), String> {
        for (path, e) in self.all_inputs() {
            if let Edge::Follows(f) = e {
                let mut visited = Vec::new();
                if self.find(&f, &mut visited)?.is_none() {
                    return Err(format!(
                        "input '{}' follows a non-existent input '{}'",
                        print_input_path(&path),
                        print_input_path(&f)
                    ));
                }
            }
        }
        Ok(())
    }

    /// The first locked node that is not locked, ignoring `path:` inputs.
    pub fn is_unlocked(&self) -> Option<FlakeRef> {
        for (_, e) in self.all_inputs() {
            if let Edge::Node(n) = e {
                if let Some(l) = &n.locked {
                    if !l.locked.input.is_locked() && l.locked.input.ty() != "path" {
                        return Some(l.locked.clone());
                    }
                }
            }
        }
        None
    }

    /// Human-readable list of added, removed and updated inputs.
    pub fn diff(old: &LockFile, new: &LockFile) -> String {
        let a = old.all_inputs();
        let b = new.all_inputs();
        let show = |e: &Edge| -> String {
            match e {
                Edge::Node(n) => match &n.locked {
                    Some(l) => describe_locked(&l.locked),
                    None => "root".into(),
                },
                Edge::Follows(p) => format!("follows '{}'", print_input_path(p)),
            }
        };
        let keys: BTreeSet<&InputPath> = a.keys().chain(b.keys()).collect();
        let mut out = String::new();
        for k in keys {
            match (a.get(k), b.get(k)) {
                (None, Some(e)) => out.push_str(&format!("• Added input '{}':\n    {}\n", print_input_path(k), show(e))),
                (Some(_), None) => out.push_str(&format!("• Removed input '{}'\n", print_input_path(k))),
                (Some(x), Some(y)) => {
                    let (sx, sy) = (show(x), show(y));
                    if sx != sy {
                        out.push_str(&format!("• Updated input '{}':\n    {sx}\n  → {sy}\n", print_input_path(k)));
                    }
                }
                _ => {}
            }
        }
        out
    }
}

pub fn describe_locked(r: &FlakeRef) -> String {
    match r.input.get_last_modified().ok().flatten() {
        Some(t) => {
            let d = cranix_fetchers::format_date(t);
            format!("'{}' ({}-{}-{})", r.to_string(), &d[0..4], &d[4..6], &d[6..8])
        }
        None => format!("'{}'", r.to_string()),
    }
}

impl PartialEq for LockFile {
    fn eq(&self, o: &LockFile) -> bool {
        self.to_string() == o.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock file written by Nix 2.24 (follows, `flake = false`, `dir`,
    /// duplicate node names) must be reproduced byte for byte.
    #[test]
    fn round_trip_nix_lock() {
        let text = include_str!("../../tests/fixtures/nix-2.24.flake.lock");
        let lf = LockFile::parse(text, "flake.lock").unwrap();
        assert_eq!(format!("{}\n", lf.to_string()), text);
        let sys = lf.find_input(&["other".into(), "systems".into()]).unwrap();
        let direct = lf.find_input(&["utils".into(), "systems".into()]).unwrap();
        assert!(Rc::ptr_eq(&sys, &direct));
        assert!(!lf.find_input(&["lib".into()]).unwrap().locked.as_ref().unwrap().is_flake);
        lf.check().unwrap();
        assert!(lf.is_unlocked().is_none());
        assert_eq!(LockFile::diff(&lf, &lf), "");
    }

    #[test]
    fn empty_lock() {
        let lf = LockFile::default();
        assert_eq!(lf.to_string(), "{\n  \"nodes\": {\n    \"root\": {}\n  },\n  \"root\": \"root\",\n  \"version\": 7\n}");
        let back = LockFile::parse(&lf.to_string(), "x").unwrap();
        assert!(back == lf);
    }

    #[test]
    fn rejects_bad_versions_and_dangling_follows() {
        assert!(LockFile::parse(r#"{"nodes":{"root":{}},"root":"root","version":4}"#, "x").is_err());
        let lf = LockFile::parse(r#"{"nodes":{"root":{"inputs":{"a":["b"]}}},"root":"root","version":7}"#, "x").unwrap();
        assert!(lf.check().unwrap_err().contains("follows a non-existent input 'b'"));
    }
}
