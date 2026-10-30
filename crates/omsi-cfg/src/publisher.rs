//! Optional publisher packs, trusted provenance and map dependency references.
use omsi_pack::{Dependency, Manifest, TrustedPublishers, VerifiedPack};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn bounded_read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid("publisher metadata must not be a symbolic link"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("publisher input exceeds its size limit"));
    }
    Ok(bytes)
}

/// One trusted source/output identity. Exact hashes do not recognize arbitrary modifications.
#[derive(Clone, Debug)]
pub struct Provenance {
    pub dependency: Dependency,
    pub asset_id: String,
    pub path: String,
    pub source_sha256: String,
    pub output_sha256: String,
    pub redistribution: bool,
    pub license: String,
    pub author: String,
    pub protected: bool,
}

#[derive(Default)]
pub struct Catalog {
    pub entries: Vec<Provenance>,
}

fn trust(content: &Path) -> io::Result<TrustedPublishers> {
    let path = content.join("Publishers.json");
    if !path.exists() {
        return Ok(TrustedPublishers::default());
    }
    TrustedPublishers::load_json(&bounded_read(&path, 1024 * 1024)?).map_err(invalid)
}

fn folders(root: &Path) -> io::Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    if std::fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(invalid("publisher folder must not be a symbolic link"));
    }
    let mut result = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            return Err(invalid("symbolic link in publisher folder"));
        }
        if entry.file_type()?.is_dir() {
            result.push(entry.path());
            if result.len() > 128 {
                return Err(invalid("too many publisher packs"));
            }
        }
    }
    result.sort();
    Ok(result)
}

fn dependency(m: &Manifest) -> Dependency {
    Dependency {
        publisher_id: m.publisher_id.clone(),
        pack_id: m.pack_id.clone(),
        version: m.version.clone(),
    }
}

fn cache_manifest(content: &Path, pack: &Path) -> io::Result<()> {
    let bytes = bounded_read(&pack.join("manifest.json"), 1024 * 1024)?;
    let sig = bounded_read(&pack.join("manifest.sig"), 1024)?;
    let root = content.join("PackIndex");
    if root.exists() && std::fs::symlink_metadata(&root)?.file_type().is_symlink() {
        return Err(invalid("publisher index must not be a symbolic link"));
    }
    std::fs::create_dir_all(&root)?;
    let target = root.join(digest(&bytes));
    if target.exists() {
        return Ok(());
    }
    let temp = root.join(format!(".new-{}", digest(&crate::vfs::random_key()?)));
    std::fs::create_dir(&temp)?;
    let result = (|| {
        std::fs::write(temp.join("manifest.json"), bytes)?;
        std::fs::write(temp.join("manifest.sig"), sig)?;
        std::fs::rename(&temp, &target)
    })();
    if temp.exists() {
        let _ = std::fs::remove_dir_all(temp);
    }
    if result.is_err() && target.is_dir() {
        return Ok(());
    }
    result
}

impl Catalog {
    pub fn load(content: &Path) -> io::Result<Self> {
        let trust = trust(content)?;
        for path in folders(&content.join("Packs"))? {
            if path.join("manifest.json").exists() {
                omsi_pack::load_manifest(&path, &trust).map_err(invalid)?;
                cache_manifest(content, &path)?;
            }
        }
        let mut catalog = Self::default();
        let mut total = 0;
        for path in folders(&content.join("PackIndex"))? {
            total += bounded_read(&path.join("manifest.json"), 1024 * 1024)?.len();
            if total > 16 * 1024 * 1024 {
                return Err(invalid("publisher index exceeds its size limit"));
            }
            let manifest = omsi_pack::load_manifest(&path, &trust).map_err(invalid)?;
            for asset in &manifest.assets {
                catalog.entries.push(Provenance {
                    dependency: dependency(&manifest),
                    asset_id: asset.id.clone(),
                    path: asset.path.clone(),
                    source_sha256: asset.source_sha256.clone(),
                    output_sha256: asset.output_sha256.clone(),
                    redistribution: manifest.redistribution,
                    license: manifest.license.clone(),
                    author: manifest.author.clone(),
                    protected: manifest.key_id.is_some(),
                });
                if catalog.entries.len() > 32768 {
                    return Err(invalid("too many indexed publisher assets"));
                }
            }
        }
        Ok(catalog)
    }

    pub fn recognize(&self, hash: &str) -> Option<&Provenance> {
        self.entries
            .iter()
            .find(|a| a.source_sha256 == hash || a.output_sha256 == hash)
    }
}

/// Local output path -> stable signed asset identity, carried alongside a shared map.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetReference {
    pub path: String,
    pub dependency: Dependency,
    pub asset_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapReferences {
    pub format_version: u32,
    pub dependencies: Vec<Dependency>,
    pub assets: Vec<AssetReference>,
}

impl Default for MapReferences {
    fn default() -> Self {
        Self {
            format_version: 1,
            dependencies: Vec::new(),
            assets: Vec::new(),
        }
    }
}

fn same(a: &Dependency, b: &Dependency) -> bool {
    a.publisher_id == b.publisher_id && a.pack_id == b.pack_id && a.version == b.version
}

fn installed(content: &Path, trust: &TrustedPublishers) -> io::Result<Vec<(PathBuf, Manifest)>> {
    let mut result: Vec<(PathBuf, Manifest)> = Vec::new();
    for path in folders(&content.join("Packs"))? {
        let manifest = omsi_pack::load_manifest(&path, trust).map_err(invalid)?;
        if result
            .iter()
            .any(|(_, m)| same(&dependency(m), &dependency(&manifest)))
        {
            return Err(invalid("duplicate installed publisher pack identity"));
        }
        result.push((path, manifest));
    }
    Ok(result)
}

/// Verify every asset before making a publisher pack visible to parsers and decoders.
pub fn mount_packs(content: &Path) -> io::Result<Vec<PathBuf>> {
    let trust = trust(content)?;
    let packs = installed(content, &trust)?;
    let mut opened = Vec::new();
    for (path, manifest) in &packs {
        for required in &manifest.dependencies {
            if !packs.iter().any(|(_, m)| same(required, &dependency(m))) {
                return Err(invalid(format!(
                    "missing publisher dependency {}/{}/{}",
                    required.publisher_id, required.pack_id, required.version
                )));
            }
        }
        let pack = VerifiedPack::open_unlocked(path, &trust, &omsi_pack::SystemKeyStore)
            .map_err(invalid)?;
        opened.push((path.clone(), Arc::new(pack)));
    }
    let mut mounts = Vec::new();
    for (path, pack) in opened {
        let mount = path.join(".mount");
        crate::vfs::mount_publisher(&mount, pack, BTreeMap::new())?;
        crate::add_content_root(mount.clone());
        mounts.push(mount);
    }
    Ok(mounts)
}

/// Called at the common world-loader boundary; ordinary maps require no new metadata.
pub fn validate_map(map_dir: &Path) -> io::Result<()> {
    let file = map_dir.join("dependencies.json");
    if !crate::vfs::is_file(&file) {
        return Ok(());
    }
    if crate::vfs::file_size(&file).is_none_or(|n| n > 1024 * 1024) {
        return Err(invalid("map dependency manifest exceeds its limit"));
    }
    let refs: MapReferences = serde_json::from_slice(&crate::vfs::read(&file)?).map_err(invalid)?;
    if refs.format_version != 1 || refs.dependencies.len() > 128 || refs.assets.len() > 4096 {
        return Err(invalid("unsupported or oversized map dependency manifest"));
    }
    let mut packs = Vec::new();
    for root in crate::content_roots()
        .into_iter()
        .filter(|r| r.join("Publishers.json").is_file())
    {
        let trusted = trust(&root)?;
        for (path, manifest) in installed(&root, &trusted)? {
            if refs
                .dependencies
                .iter()
                .any(|d| same(d, &dependency(&manifest)))
            {
                let pack = VerifiedPack::open_unlocked(&path, &trusted, &omsi_pack::SystemKeyStore)
                    .map_err(invalid)?;
                packs.push((path, Arc::new(pack)));
            }
        }
    }
    for required in &refs.dependencies {
        if !packs
            .iter()
            .any(|(_, p)| same(required, &dependency(p.manifest())))
        {
            return Err(invalid(format!(
                "missing or wrong-version publisher dependency {}/{}/{}",
                required.publisher_id, required.pack_id, required.version
            )));
        }
    }
    let mut seen = BTreeSet::new();
    for reference in &refs.assets {
        if !seen.insert(reference.path.to_lowercase()) {
            return Err(invalid("duplicate dependency alias"));
        }
        if !refs
            .dependencies
            .iter()
            .any(|d| same(d, &reference.dependency))
        {
            return Err(invalid("asset names an undeclared dependency"));
        }
    }
    // A separate virtual root keeps aliases out of the map's editable files.
    for (index, (_, pack)) in packs.into_iter().enumerate() {
        let mut aliases = BTreeMap::new();
        for reference in refs
            .assets
            .iter()
            .filter(|r| same(&r.dependency, &dependency(pack.manifest())))
        {
            let asset = pack
                .assets()
                .iter()
                .find(|a| a.id == reference.asset_id)
                .ok_or_else(|| invalid("dependency asset identity was not found"))?;
            aliases.insert(reference.path.clone(), asset.path.clone());
        }
        if !aliases.is_empty() {
            let mount = map_dir.join(format!(".publisher-dependencies/{index}"));
            crate::vfs::mount_publisher(&mount, pack, aliases)?;
            crate::add_content_root_first(mount);
        }
    }
    Ok(())
}
