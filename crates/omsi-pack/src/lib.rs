//! Versioned publisher packs for optional provenance and protected map assets.
//!
//! Manifests are canonical JSON signed by an Ed25519 publisher key trusted by the player.
//! Encrypted packs contain per-file AES-256-GCM chunks; decryption returns at most one
//! bounded asset to the caller and never writes its plaintext to the pack directory.

use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const FORMAT_VERSION: u32 = 1;
const MANIFEST_LIMIT: usize = 1024 * 1024;
const TRUST_LIMIT: usize = 256 * 1024;
const ENTITLEMENT_LIMIT: usize = 64 * 1024;
const MAX_ASSETS: usize = 4096;
const MAX_DEPENDENCIES: usize = 256;
const CHUNK_SIZE: usize = 64 * 1024;
const MAX_ASSET_SIZE: u64 = 64 * 1024 * 1024;
const MAX_PACK_SIZE: u64 = 1024 * 1024 * 1024;
const TAG_SIZE: usize = 16;
const SERVICE: &str = "org.openomsi.protected-pack";

pub type Result<T> = std::result::Result<T, PackError>;

#[derive(Debug)]
pub enum PackError {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
    UntrustedPublisher,
    InvalidSignature,
    MissingKey,
    WrongKey,
    Cancelled,
    Expired,
    KeyNotFound,
    SecureStorageUnavailable,
    SecureStorage(String),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
            Self::Invalid(s) => write!(f, "invalid publisher pack: {s}"),
            Self::UntrustedPublisher => f.write_str("publisher signing key is not trusted"),
            Self::InvalidSignature => f.write_str("publisher signature is invalid"),
            Self::MissingKey => {
                f.write_str("a valid offline entitlement is needed to unlock this pack")
            }
            Self::WrongKey => f.write_str("the protected pack key is unavailable or incorrect"),
            Self::Cancelled => f.write_str("pack creation was cancelled"),
            Self::Expired => f.write_str("the offline entitlement has expired"),
            Self::KeyNotFound => f.write_str("protected pack key is not stored on this device"),
            Self::SecureStorageUnavailable => {
                f.write_str("native protected key storage is unavailable on this platform")
            }
            Self::SecureStorage(s) => write!(f, "native protected key storage failed: {s}"),
        }
    }
}

impl std::error::Error for PackError {}
impl From<io::Error> for PackError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for PackError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub publisher_id: String,
    pub pack_id: String,
    /// Exact pack version required by this manifest.
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    pub publisher_id: String,
    pub author: String,
    pub pack_id: String,
    pub version: String,
    pub license: String,
    pub redistribution: bool,
    /// Lowercase SHA-256 of this pack's random 32-byte AES key; not the key itself.
    pub key_id: Option<String>,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// Stable publisher asset identity; it survives a file rename.
    pub id: String,
    /// Safe forward-slash game path.
    pub path: String,
    /// SHA-256 of the original source bytes before conversion.
    pub source_sha256: String,
    /// SHA-256 of the bytes stored in the pack after conversion.
    pub output_sha256: String,
    pub size: u64,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub file: String,
    pub plaintext_size: u32,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub publisher_id: String,
    pub author: String,
    pub pack_id: String,
    pub version: String,
    pub license: String,
    pub redistribution: bool,
    /// Hash of the Ed25519 public key that signed the manifest.
    pub signing_key_id: String,
    /// Present only for AES-GCM protected packs.
    pub key_id: Option<String>,
    pub dependencies: Vec<Dependency>,
    pub assets: Vec<Asset>,
}

pub struct AssetInput {
    pub id: String,
    pub path: String,
    pub source_sha256: String,
    pub bytes: Vec<u8>,
}

/// Ed25519 publisher signing key. Debug output deliberately omits key bytes.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl SigningKey {
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self> {
        let document = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|_| PackError::Invalid("could not generate signing key"))?;
        Self::from_pkcs8(document.as_ref())
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            pair: Ed25519KeyPair::from_pkcs8(bytes)
                .map_err(|_| PackError::Invalid("invalid PKCS#8 Ed25519 private key"))?,
            pkcs8: bytes.to_vec(),
        })
    }

    pub fn generate_pkcs8(rng: &dyn SecureRandom) -> Result<(Self, Vec<u8>)> {
        let document = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|_| PackError::Invalid("could not generate signing key"))?;
        let bytes = document.as_ref().to_vec();
        Ok((Self::from_pkcs8(&bytes)?, bytes))
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }

    pub fn key_id(&self) -> String {
        sha256_hex(&self.public_key())
    }

    pub fn save_private_key(&self, path: &Path) -> Result<()> {
        write_atomic(path, &self.pkcs8)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPublishers {
    publishers: BTreeMap<String, BTreeMap<String, [u8; 32]>>,
}

impl TrustedPublishers {
    pub fn insert(
        &mut self,
        publisher_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) {
        self.publishers
            .entry(publisher_id.into())
            .or_default()
            .insert(key_id.into(), public_key);
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn load_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > TRUST_LIMIT {
            return Err(PackError::Invalid("publisher trust file is too large"));
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let bytes = read_bounded_file(path, TRUST_LIMIT)?;
        Self::load_json(&bytes)
    }

    pub fn save_file(&self, path: &Path) -> Result<()> {
        write_atomic(path, &self.to_json()?)
    }

    fn key(&self, publisher: &str, key_id: &str) -> Option<&[u8; 32]> {
        self.publishers.get(publisher)?.get(key_id)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Generate a fresh random content key for each protected pack.
pub fn random_content_key() -> Result<[u8; 32]> {
    let mut key = [0; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| PackError::Invalid("operating system random source failed"))?;
    Ok(key)
}

/// Read and verify the signed manifest without opening any asset chunks. This is also used
/// for cached provenance snapshots, which remain useful after the original pack is removed.
pub fn load_manifest(pack: &Path, trusted: &TrustedPublishers) -> Result<Manifest> {
    let root = pack.canonicalize()?;
    if !root.is_dir() {
        return Err(PackError::Invalid("pack root is not a directory"));
    }
    let bytes = read_bounded_file(&root.join("manifest.json"), MANIFEST_LIMIT)?;
    let signature = read_bounded_file(&root.join("manifest.sig"), 64)?;
    if signature.len() != 64 {
        return Err(PackError::InvalidSignature);
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    validate_manifest(&manifest)?;
    if serde_json::to_vec(&manifest)? != bytes {
        return Err(PackError::Invalid("manifest JSON is not canonical"));
    }
    let public = trusted
        .key(&manifest.publisher_id, &manifest.signing_key_id)
        .ok_or(PackError::UntrustedPublisher)?;
    if sha256_hex(public) != manifest.signing_key_id {
        return Err(PackError::Invalid(
            "publisher key id does not match its public key",
        ));
    }
    UnparsedPublicKey::new(&signature::ED25519, public)
        .verify(&bytes, &signature)
        .map_err(|_| PackError::InvalidSignature)?;
    Ok(manifest)
}

/// Load a manifest only when its detached publisher signature matches this publisher's signing
/// key. This is used by the offline issuer and avoids treating a key supplied by the pack as
/// trusted input.
pub fn load_manifest_signed_by(pack: &Path, signer: &SigningKey) -> Result<Manifest> {
    let bytes = read_bounded_file(&pack.join("manifest.json"), MANIFEST_LIMIT)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    validate_identity(&manifest.publisher_id)?;
    if manifest.signing_key_id != signer.key_id() {
        return Err(PackError::UntrustedPublisher);
    }
    let mut trusted = TrustedPublishers::default();
    trusted.insert(
        manifest.publisher_id.clone(),
        signer.key_id(),
        signer.public_key(),
    );
    load_manifest(pack, &trusted)
}

/// Write a complete pack to a new directory. For each protected pack the publisher must pass
/// one fresh key from [`random_content_key`] and set `metadata.key_id` to its SHA-256. Never
/// reuse that key on a later pack. Encrypted files use unique random nonces and independently
/// authenticated chunks no larger than 64 KiB. The destination must not already exist.
pub fn create_pack(
    destination: &Path,
    metadata: PackMetadata,
    inputs: &[AssetInput],
    signer: &SigningKey,
    content_key: Option<&[u8; 32]>,
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    if destination.exists() {
        return Err(PackError::Invalid("destination already exists"));
    }
    validate_metadata(&metadata)?;
    if inputs.is_empty() || inputs.len() > MAX_ASSETS {
        return Err(PackError::Invalid(
            "asset count is outside the supported limit",
        ));
    }
    if metadata.key_id.is_some() != content_key.is_some() {
        return Err(PackError::Invalid(
            "protected pack metadata must include exactly one key id and content key",
        ));
    }
    if let (Some(id), Some(key)) = (&metadata.key_id, content_key) {
        if id != &sha256_hex(key) {
            return Err(PackError::Invalid(
                "content key id must be its SHA-256 hash",
            ));
        }
    }

    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    let mut assets = Vec::with_capacity(inputs.len());
    for input in inputs {
        validate_identity(&input.id)?;
        validate_game_path(&input.path)?;
        if !ids.insert(input.id.clone()) {
            return Err(PackError::Invalid("duplicate asset identity"));
        }
        if !paths.insert(input.path.to_lowercase()) {
            return Err(PackError::Invalid("duplicate or case-colliding asset path"));
        }
        if !is_sha256(&input.source_sha256) {
            return Err(PackError::Invalid(
                "source hash must be 64 lowercase hexadecimal characters",
            ));
        }
        if input.bytes.len() as u64 > MAX_ASSET_SIZE {
            return Err(PackError::Invalid("asset exceeds 64 MiB"));
        }
        total = total
            .checked_add(input.bytes.len() as u64)
            .ok_or(PackError::Invalid("pack size overflow"))?;
        if total > MAX_PACK_SIZE {
            return Err(PackError::Invalid("pack exceeds 1 GiB"));
        }
        assets.push(Asset {
            id: input.id.clone(),
            path: input.path.clone(),
            source_sha256: input.source_sha256.clone(),
            output_sha256: sha256_hex(&input.bytes),
            size: input.bytes.len() as u64,
            chunks: Vec::new(),
        });
    }
    let mut manifest = Manifest {
        format_version: FORMAT_VERSION,
        publisher_id: metadata.publisher_id,
        author: metadata.author,
        pack_id: metadata.pack_id,
        version: metadata.version,
        license: metadata.license,
        redistribution: metadata.redistribution,
        signing_key_id: signer.key_id(),
        key_id: metadata.key_id,
        dependencies: metadata.dependencies,
        assets,
    };
    let parent = destination
        .parent()
        .ok_or(PackError::Invalid("destination needs a parent directory"))?;
    if !parent.is_dir() {
        return Err(PackError::Invalid("destination parent does not exist"));
    }
    fs::create_dir(destination)?;
    let mut written = Vec::<PathBuf>::new();
    let mut created_dirs = vec![destination.to_path_buf()];
    let result = (|| {
        let cipher = match content_key {
            Some(k) => Some(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, k)
                    .map_err(|_| PackError::Invalid("invalid AES-256 key"))?,
            )),
            None => None,
        };
        let (publisher_id, pack_id, version) = (
            manifest.publisher_id.clone(),
            manifest.pack_id.clone(),
            manifest.version.clone(),
        );
        let mut used_nonces = BTreeSet::new();
        for (asset, input) in manifest.assets.iter_mut().zip(inputs) {
            if cancelled.load(Ordering::Relaxed) {
                return Err(PackError::Cancelled);
            }
            let opaque = sha256_hex(asset.id.as_bytes());
            if let Some(cipher) = &cipher {
                let count = input.bytes.len().max(1).div_ceil(CHUNK_SIZE);
                for (index, chunk) in input.bytes.chunks(CHUNK_SIZE).enumerate() {
                    if cancelled.load(Ordering::Relaxed) {
                        return Err(PackError::Cancelled);
                    }
                    let nonce_bytes = random_nonce(&mut used_nonces)?;
                    let aad = chunk_aad_fields(
                        &publisher_id,
                        &pack_id,
                        &version,
                        asset,
                        index as u32,
                        count as u32,
                    );
                    let mut body = chunk.to_vec();
                    cipher
                        .seal_in_place_append_tag(
                            Nonce::assume_unique_for_key(nonce_bytes),
                            Aad::from(aad.as_slice()),
                            &mut body,
                        )
                        .map_err(|_| PackError::Invalid("AES-GCM encryption failed"))?;
                    let mut blob = nonce_bytes.to_vec();
                    blob.append(&mut body);
                    let file = format!("assets/{opaque}/{index:08}.bin");
                    write_pack_file(destination, &file, &blob, &mut written, &mut created_dirs)?;
                    asset.chunks.push(Chunk {
                        file,
                        plaintext_size: chunk.len() as u32,
                        ciphertext_sha256: sha256_hex(&blob),
                    });
                }
                if input.bytes.is_empty() {
                    let nonce_bytes = random_nonce(&mut used_nonces)?;
                    let aad = chunk_aad_fields(&publisher_id, &pack_id, &version, asset, 0, 1);
                    let mut body = Vec::new();
                    cipher
                        .seal_in_place_append_tag(
                            Nonce::assume_unique_for_key(nonce_bytes),
                            Aad::from(aad.as_slice()),
                            &mut body,
                        )
                        .map_err(|_| PackError::Invalid("AES-GCM encryption failed"))?;
                    let mut blob = nonce_bytes.to_vec();
                    blob.append(&mut body);
                    let file = format!("assets/{opaque}/00000000.bin");
                    write_pack_file(destination, &file, &blob, &mut written, &mut created_dirs)?;
                    asset.chunks.push(Chunk {
                        file,
                        plaintext_size: 0,
                        ciphertext_sha256: sha256_hex(&blob),
                    });
                }
            } else {
                let file = format!("assets/{opaque}/plain.bin");
                write_pack_file(
                    destination,
                    &file,
                    &input.bytes,
                    &mut written,
                    &mut created_dirs,
                )?;
            }
        }
        validate_manifest(&manifest)?;
        let bytes = serde_json::to_vec(&manifest)?;
        if bytes.len() > MANIFEST_LIMIT {
            return Err(PackError::Invalid("signed manifest exceeds 1 MiB"));
        }
        let signature = signer.pair.sign(&bytes);
        write_pack_file(
            destination,
            "manifest.sig",
            signature.as_ref(),
            &mut written,
            &mut created_dirs,
        )?;
        write_pack_file(
            destination,
            "manifest.json",
            &bytes,
            &mut written,
            &mut created_dirs,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        for path in written.iter().rev() {
            let _ = fs::remove_file(path);
        }
        for dir in created_dirs.iter().rev() {
            let _ = fs::remove_dir(dir);
        }
        return Err(error);
    }
    Ok(manifest)
}

pub struct VerifiedPack {
    root: PathBuf,
    manifest: Manifest,
    content_key: Option<[u8; 32]>,
}

impl Drop for VerifiedPack {
    fn drop(&mut self) {
        if let Some(key) = self.content_key.as_mut() {
            key.zeroize();
        }
    }
}

impl VerifiedPack {
    pub fn open_for_authoring(
        root: &Path,
        trusted: &TrustedPublishers,
        content_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let manifest = load_manifest(root, trusted)?;
        if manifest.key_id.is_some() != content_key.is_some() {
            return Err(PackError::MissingKey);
        }
        if let (Some(id), Some(key)) = (&manifest.key_id, &content_key) {
            if id != &sha256_hex(key) {
                return Err(PackError::WrongKey);
            }
        }
        let pack = Self {
            root: root.canonicalize()?,
            manifest,
            content_key,
        };
        pack.verify_all()?;
        Ok(pack)
    }

    /// Open an encrypted pack only with a previously verified, unexpired entitlement stored
    /// by the OS key store. Its signature and exact manifest binding are checked on every open.
    pub fn open_unlocked(
        root: &Path,
        trusted: &TrustedPublishers,
        keys: &dyn KeyStore,
    ) -> Result<Self> {
        let manifest = load_manifest(root, trusted)?;
        if manifest.key_id.is_none() {
            let pack = Self {
                root: root.canonicalize()?,
                manifest,
                content_key: None,
            };
            pack.verify_all()?;
            return Ok(pack);
        }
        let unsigned_key = manifest.key_id.as_deref().unwrap_or_default();
        let scope = entitlement_scope(&manifest, unsigned_key)?;
        let mut bytes = keys.load(&scope)?;
        let verified = verify_entitlement(&manifest, &bytes, trusted);
        bytes.zeroize();
        let entitlement = verified?;
        let content_key = entitlement.content_key;
        drop(entitlement);
        let pack = Self {
            root: root.canonicalize()?,
            manifest,
            content_key: Some(content_key),
        };
        pack.verify_all()?;
        Ok(pack)
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn assets(&self) -> &[Asset] {
        &self.manifest.assets
    }

    /// Authenticate a requested asset fully before returning plaintext to a decoder.
    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        let asset = self
            .manifest
            .assets
            .iter()
            .find(|a| a.path.eq_ignore_ascii_case(path))
            .ok_or(PackError::Invalid("asset is not in the signed manifest"))?;
        if asset.size > MAX_ASSET_SIZE {
            return Err(PackError::Invalid("asset exceeds 64 MiB"));
        }
        let mut out = Vec::with_capacity(asset.size as usize);
        if let Some(key) = &self.content_key {
            let cipher = LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, key).map_err(|_| PackError::WrongKey)?,
            );
            for (index, chunk) in asset.chunks.iter().enumerate() {
                let blob = self.read_chunk(chunk)?;
                let nonce = Nonce::try_assume_unique_for_key(&blob[..NONCE_LEN])
                    .map_err(|_| PackError::Invalid("invalid chunk nonce"))?;
                let mut body = blob[NONCE_LEN..].to_vec();
                let aad = chunk_aad(
                    &self.manifest,
                    asset,
                    index as u32,
                    asset.chunks.len() as u32,
                );
                let plain = cipher
                    .open_in_place(nonce, Aad::from(aad.as_slice()), &mut body)
                    .map_err(|_| PackError::WrongKey)?;
                if plain.len() != chunk.plaintext_size as usize {
                    return Err(PackError::Invalid(
                        "authenticated chunk size does not match manifest",
                    ));
                }
                out.extend_from_slice(plain);
                body.zeroize();
            }
        } else {
            let opaque = sha256_hex(asset.id.as_bytes());
            out = read_bounded_file(
                &self.root.join(format!("assets/{opaque}/plain.bin")),
                MAX_ASSET_SIZE as usize,
            )?;
        }
        if out.len() as u64 != asset.size || sha256_hex(&out) != asset.output_sha256 {
            return Err(PackError::Invalid(
                "asset bytes do not match the signed output hash",
            ));
        }
        Ok(out)
    }

    /// Check every signed blob while keeping memory to one authenticated chunk at a time.
    pub fn verify_all(&self) -> Result<()> {
        for asset in &self.manifest.assets {
            if let Some(key) = &self.content_key {
                let cipher = LessSafeKey::new(
                    UnboundKey::new(&AES_256_GCM, key).map_err(|_| PackError::WrongKey)?,
                );
                let mut digest = Sha256::new();
                let mut size = 0u64;
                for (index, chunk) in asset.chunks.iter().enumerate() {
                    let blob = self.read_chunk(chunk)?;
                    let nonce = Nonce::try_assume_unique_for_key(&blob[..NONCE_LEN])
                        .map_err(|_| PackError::Invalid("invalid chunk nonce"))?;
                    let mut body = blob[NONCE_LEN..].to_vec();
                    let aad = chunk_aad(
                        &self.manifest,
                        asset,
                        index as u32,
                        asset.chunks.len() as u32,
                    );
                    let plain = cipher
                        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut body)
                        .map_err(|_| PackError::WrongKey)?;
                    if plain.len() != chunk.plaintext_size as usize {
                        return Err(PackError::Invalid(
                            "authenticated chunk size does not match manifest",
                        ));
                    }
                    size += plain.len() as u64;
                    digest.update(&*plain);
                    body.zeroize();
                }
                if size != asset.size
                    || hex_digest(digest.finalize().as_slice()) != asset.output_sha256
                {
                    return Err(PackError::Invalid(
                        "asset bytes do not match the signed output hash",
                    ));
                }
            } else {
                let bytes = self.read(&asset.path)?;
                drop(bytes);
            }
        }
        Ok(())
    }

    fn read_chunk(&self, chunk: &Chunk) -> Result<Vec<u8>> {
        let path = self.root.join(&chunk.file);
        let blob = read_bounded_file(&path, CHUNK_SIZE + NONCE_LEN + TAG_SIZE)?;
        if blob.len() < NONCE_LEN + TAG_SIZE || sha256_hex(&blob) != chunk.ciphertext_sha256 {
            return Err(PackError::Invalid(
                "chunk is missing, truncated, or changed",
            ));
        }
        Ok(blob)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entitlement {
    pub format_version: u32,
    pub publisher_id: String,
    pub signing_key_id: String,
    pub pack_id: String,
    pub pack_version: String,
    pub manifest_sha256: String,
    pub key_id: String,
    pub expires_unix: u64,
    /// This signed key grant is a bearer secret. Deliver it confidentially; anyone who obtains
    /// it can copy it to another account/device, even after the original recipient unlocks it.
    pub content_key: [u8; 32],
}

impl Drop for Entitlement {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEntitlement {
    entitlement: Entitlement,
    signature: Vec<u8>,
}

/// Create a publisher-signed offline bearer entitlement for one exact pack revision.
pub fn issue_entitlement(
    manifest: &Manifest,
    content_key: [u8; 32],
    expires_unix: u64,
    signer: &SigningKey,
) -> Result<Vec<u8>> {
    if manifest.key_id.as_deref() != Some(sha256_hex(&content_key).as_str())
        || signer.key_id() != manifest.signing_key_id
        || expires_unix <= now_unix()?
    {
        return Err(PackError::Invalid(
            "entitlement signer, key id, or expiry does not match the pack",
        ));
    }
    let entitlement = Entitlement {
        format_version: FORMAT_VERSION,
        publisher_id: manifest.publisher_id.clone(),
        signing_key_id: signer.key_id(),
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        manifest_sha256: sha256_hex(&serde_json::to_vec(manifest)?),
        key_id: manifest.key_id.clone().unwrap(),
        expires_unix,
        content_key,
    };
    let bytes = serde_json::to_vec(&entitlement)?;
    let signed = SignedEntitlement {
        entitlement,
        signature: signer.pair.sign(&bytes).as_ref().to_vec(),
    };
    Ok(serde_json::to_vec(&signed)?)
}

pub trait KeyStore {
    /// Store the signed entitlement envelope as an opaque native-protected secret.
    fn store(&self, scope: &str, signed_entitlement: &[u8]) -> Result<()>;
    fn load(&self, scope: &str) -> Result<Vec<u8>>;
    fn delete(&self, scope: &str) -> Result<()>;
}

/// OS-native key store: Keychain on macOS and user-scoped DPAPI on Windows.
pub struct SystemKeyStore;

impl KeyStore for SystemKeyStore {
    fn store(&self, scope: &str, signed_entitlement: &[u8]) -> Result<()> {
        native_store(scope, signed_entitlement)
    }
    fn load(&self, scope: &str) -> Result<Vec<u8>> {
        native_load(scope)
    }
    fn delete(&self, scope: &str) -> Result<()> {
        native_delete(scope)
    }
}

/// Verify a publisher-signed bearer entitlement against the pack's signed manifest, then
/// persist its content key in the caller's native protected store.
pub fn unlock(
    pack_root: &Path,
    bytes: &[u8],
    trusted: &TrustedPublishers,
    keys: &dyn KeyStore,
) -> Result<Manifest> {
    if bytes.len() > ENTITLEMENT_LIMIT {
        return Err(PackError::Invalid("offline entitlement is too large"));
    }
    let manifest = load_manifest(pack_root, trusted)?;
    let entitlement = verify_entitlement(&manifest, bytes, trusted)?;
    let scope = entitlement_scope(&manifest, &entitlement.key_id)?;
    keys.store(&scope, bytes)?;
    Ok(manifest)
}

/// Remove the OS-protected entitlement for one signed pack revision. The scope includes the
/// canonical manifest digest and content-key ID, so this cannot remove another pack's grant.
pub fn forget_unlock(
    pack_root: &Path,
    trusted: &TrustedPublishers,
    keys: &dyn KeyStore,
) -> Result<()> {
    let manifest = load_manifest(pack_root, trusted)?;
    let Some(key_id) = manifest.key_id.as_deref() else {
        return Ok(());
    };
    let scope = entitlement_scope(&manifest, key_id)?;
    match keys.delete(&scope) {
        Err(PackError::KeyNotFound) => Ok(()),
        result => result,
    }
}

fn verify_entitlement(
    manifest: &Manifest,
    bytes: &[u8],
    trusted: &TrustedPublishers,
) -> Result<Entitlement> {
    if bytes.len() > ENTITLEMENT_LIMIT {
        return Err(PackError::Invalid("offline entitlement is too large"));
    }
    let signed: SignedEntitlement = serde_json::from_slice(bytes)?;
    let e = &signed.entitlement;
    let canonical = serde_json::to_vec(e)?;
    let public = trusted
        .key(&e.publisher_id, &e.signing_key_id)
        .ok_or(PackError::UntrustedPublisher)?;
    if e.format_version != FORMAT_VERSION || sha256_hex(public) != e.signing_key_id {
        return Err(PackError::Invalid(
            "unsupported or mismatched entitlement signer",
        ));
    }
    UnparsedPublicKey::new(&signature::ED25519, public)
        .verify(&canonical, &signed.signature)
        .map_err(|_| PackError::InvalidSignature)?;
    if e.expires_unix <= now_unix()? {
        return Err(PackError::Expired);
    }
    if e.key_id != sha256_hex(&e.content_key)
        || e.publisher_id != manifest.publisher_id
        || e.signing_key_id != manifest.signing_key_id
        || e.pack_id != manifest.pack_id
        || e.pack_version != manifest.version
        || e.key_id != manifest.key_id.as_deref().unwrap_or("")
        || e.manifest_sha256 != sha256_hex(&serde_json::to_vec(manifest)?)
    {
        return Err(PackError::Invalid(
            "offline entitlement is for another pack, version, or signing key",
        ));
    }
    Ok(signed.entitlement)
}

fn entitlement_scope(manifest: &Manifest, key_id: &str) -> Result<String> {
    let mut bytes = serde_json::to_vec(manifest)?;
    bytes.push(0);
    bytes.extend_from_slice(key_id.as_bytes());
    Ok(sha256_hex(&bytes))
}

fn validate_scope(scope: &str) -> Result<()> {
    if is_sha256(scope) {
        Ok(())
    } else {
        Err(PackError::Invalid("native entitlement scope is malformed"))
    }
}

fn validate_metadata(m: &PackMetadata) -> Result<()> {
    validate_identity(&m.publisher_id)?;
    validate_identity(&m.author)?;
    validate_identity(&m.pack_id)?;
    validate_identity(&m.version)?;
    validate_identity(&m.license)?;
    if let Some(id) = &m.key_id {
        validate_identity(id)?;
    }
    if m.dependencies.len() > MAX_DEPENDENCIES {
        return Err(PackError::Invalid("too many pack dependencies"));
    }
    let mut deps = BTreeSet::new();
    for d in &m.dependencies {
        validate_identity(&d.publisher_id)?;
        validate_identity(&d.pack_id)?;
        validate_identity(&d.version)?;
        if !deps.insert((d.publisher_id.as_str(), d.pack_id.as_str())) {
            return Err(PackError::Invalid("duplicate pack dependency"));
        }
    }
    Ok(())
}

fn validate_manifest(m: &Manifest) -> Result<()> {
    if m.format_version != FORMAT_VERSION {
        return Err(PackError::Invalid("unsupported pack format version"));
    }
    validate_identity(&m.publisher_id)?;
    validate_identity(&m.author)?;
    validate_identity(&m.pack_id)?;
    validate_identity(&m.version)?;
    validate_identity(&m.license)?;
    validate_sha_field(&m.signing_key_id)?;
    if let Some(k) = &m.key_id {
        validate_identity(k)?;
    }
    if m.dependencies.len() > MAX_DEPENDENCIES || m.assets.is_empty() || m.assets.len() > MAX_ASSETS
    {
        return Err(PackError::Invalid(
            "manifest count exceeds supported bounds",
        ));
    }
    let mut deps = BTreeSet::new();
    for d in &m.dependencies {
        validate_identity(&d.publisher_id)?;
        validate_identity(&d.pack_id)?;
        validate_identity(&d.version)?;
        if !deps.insert((d.publisher_id.as_str(), d.pack_id.as_str())) {
            return Err(PackError::Invalid("duplicate pack dependency"));
        }
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for a in &m.assets {
        validate_identity(&a.id)?;
        validate_game_path(&a.path)?;
        validate_sha_field(&a.source_sha256)?;
        validate_sha_field(&a.output_sha256)?;
        if !ids.insert(&a.id) || !paths.insert(a.path.to_lowercase()) {
            return Err(PackError::Invalid(
                "duplicate asset identity or case-colliding path",
            ));
        }
        if a.size > MAX_ASSET_SIZE {
            return Err(PackError::Invalid("asset exceeds 64 MiB"));
        }
        total = total
            .checked_add(a.size)
            .ok_or(PackError::Invalid("pack size overflow"))?;
        if total > MAX_PACK_SIZE {
            return Err(PackError::Invalid("pack exceeds 1 GiB"));
        }
        if m.key_id.is_none() {
            if !a.chunks.is_empty() {
                return Err(PackError::Invalid(
                    "plain asset unexpectedly lists encrypted chunks",
                ));
            }
        } else {
            let expected = a.size.max(1).div_ceil(CHUNK_SIZE as u64) as usize;
            if a.chunks.len() != expected {
                return Err(PackError::Invalid(
                    "encrypted asset chunk count does not match its size",
                ));
            }
            let opaque = sha256_hex(a.id.as_bytes());
            let mut sum = 0u64;
            for (index, c) in a.chunks.iter().enumerate() {
                let expected_file = format!("assets/{opaque}/{index:08}.bin");
                if c.file != expected_file
                    || c.plaintext_size as usize > CHUNK_SIZE
                    || !is_sha256(&c.ciphertext_sha256)
                {
                    return Err(PackError::Invalid(
                        "unsafe or inconsistent encrypted chunk record",
                    ));
                }
                if index + 1 < a.chunks.len() && c.plaintext_size as usize != CHUNK_SIZE {
                    return Err(PackError::Invalid(
                        "non-final encrypted chunk is not 64 KiB",
                    ));
                }
                sum += c.plaintext_size as u64;
            }
            if sum != a.size {
                return Err(PackError::Invalid(
                    "encrypted chunk sizes do not match asset size",
                ));
            }
        }
    }
    Ok(())
}

fn validate_game_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
    {
        return Err(PackError::Invalid(
            "asset path must be a safe forward-slash relative game path",
        ));
    }
    for part in path.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with([' ', '.'])
            || part.chars().any(char::is_control)
        {
            return Err(PackError::Invalid(
                "asset path contains an unsafe component",
            ));
        }
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(PackError::Invalid(
                "asset path uses a reserved Windows name",
            ));
        }
    }
    Ok(())
}

fn validate_identity(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(|c| c.is_control()) {
        return Err(PackError::Invalid(
            "metadata identity is empty, too long, or contains control bytes",
        ));
    }
    Ok(())
}

fn validate_sha_field(value: &str) -> Result<()> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(PackError::Invalid("SHA-256 value is malformed"))
    }
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn hex_digest(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn chunk_aad(m: &Manifest, a: &Asset, index: u32, count: u32) -> Vec<u8> {
    chunk_aad_fields(&m.publisher_id, &m.pack_id, &m.version, a, index, count)
}

fn chunk_aad_fields(
    publisher_id: &str,
    pack_id: &str,
    version: &str,
    a: &Asset,
    index: u32,
    count: u32,
) -> Vec<u8> {
    let mut out = b"openOMSI protected pack chunk v1\0".to_vec();
    for s in [publisher_id, pack_id, version, &a.id, &a.path] {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&a.size.to_be_bytes());
    out
}

fn random_nonce(used: &mut BTreeSet<[u8; NONCE_LEN]>) -> Result<[u8; NONCE_LEN]> {
    for _ in 0..8 {
        let mut bytes = [0; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| PackError::Invalid("operating system random source failed"))?;
        if used.insert(bytes) {
            return Ok(bytes);
        }
    }
    Err(PackError::Invalid(
        "operating system random source repeated a chunk nonce",
    ))
}

fn read_bounded_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    ensure_regular_file(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() > max as u64 {
        return Err(PackError::Invalid("file exceeds its size limit"));
    }
    let f = File::open(path)?;
    let mut out = Vec::with_capacity(metadata.len() as usize);
    f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(PackError::Invalid("file exceeds its size limit"));
    }
    Ok(out)
}

fn ensure_regular_file(path: &Path) -> Result<()> {
    for component in path.ancestors().take_while(|p| !p.as_os_str().is_empty()) {
        if !component.exists() {
            return Err(PackError::Invalid("pack path does not exist"));
        }
        let metadata = fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink() {
            return Err(PackError::Invalid(
                "symbolic links are not allowed in a pack",
            ));
        }
    }
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(PackError::Invalid("pack entry is not a regular file"));
    }
    Ok(())
}

fn write_pack_file(
    root: &Path,
    relative: &str,
    bytes: &[u8],
    written: &mut Vec<PathBuf>,
    created_dirs: &mut Vec<PathBuf>,
) -> Result<()> {
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(PackError::Invalid("unsafe generated file path"));
    }
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        let rel_parent = parent
            .strip_prefix(root)
            .map_err(|_| PackError::Invalid("generated file escaped the pack"))?;
        let mut dir = root.to_path_buf();
        for part in rel_parent.components() {
            let std::path::Component::Normal(part) = part else {
                return Err(PackError::Invalid("generated directory path is unsafe"));
            };
            dir.push(part);
            if !dir.exists() {
                fs::create_dir(&dir)?;
                created_dirs.push(dir.clone());
            } else if fs::symlink_metadata(&dir)?.file_type().is_symlink() || !dir.is_dir() {
                return Err(PackError::Invalid("generated pack directory is unsafe"));
            }
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    written.push(path);
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(PackError::Invalid("trust file already exists"));
    }
    let parent = path
        .parent()
        .ok_or(PackError::Invalid("trust file needs a parent"))?;
    let tmp = parent.join(format!(".omsi-trust-{}.tmp", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PackError::Invalid("system clock predates Unix time"))?
        .as_secs())
}

#[cfg(target_os = "macos")]
fn native_store(scope: &str, secret: &[u8]) -> Result<()> {
    validate_scope(scope)?;
    security_framework::passwords::set_generic_password(SERVICE, scope, secret)
        .map_err(|e| PackError::SecureStorage(e.to_string()))
}

#[cfg(target_os = "macos")]
fn native_load(scope: &str) -> Result<Vec<u8>> {
    validate_scope(scope)?;
    security_framework::passwords::generic_password(
        security_framework::passwords::PasswordOptions::new_generic_password(SERVICE, scope),
    )
    .map_err(|e| PackError::SecureStorage(e.to_string()))
}

#[cfg(target_os = "macos")]
fn native_delete(scope: &str) -> Result<()> {
    validate_scope(scope)?;
    security_framework::passwords::delete_generic_password(SERVICE, scope)
        .map_err(|e| PackError::SecureStorage(e.to_string()))
}

#[cfg(windows)]
fn native_store(scope: &str, secret: &[u8]) -> Result<()> {
    use std::ffi::c_void;
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };
    validate_scope(scope)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: secret.len() as u32,
        pbData: secret.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = Sha256::digest(scope.as_bytes());
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            windows::core::PCWSTR::null(),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|e| PackError::SecureStorage(e.to_string()))?;
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut c_void)));
    }
    write_windows_key(scope, &protected)
}

#[cfg(windows)]
fn native_load(scope: &str) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    validate_scope(scope)?;
    let path = windows_key_path(scope)?;
    let encrypted = read_bounded_file(&path, ENTITLEMENT_LIMIT + 4096)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = Sha256::digest(scope.as_bytes());
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|_| {
        PackError::SecureStorage(
            "DPAPI could not unlock this key for the current Windows user".into(),
        )
    })?;
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut c_void)));
    }
    if result.len() > ENTITLEMENT_LIMIT {
        return Err(PackError::Invalid(
            "stored entitlement exceeds its size limit",
        ));
    }
    Ok(result)
}

#[cfg(windows)]
fn native_delete(scope: &str) -> Result<()> {
    validate_scope(scope)?;
    let path = windows_key_path(scope)?;
    fs::remove_file(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            PackError::KeyNotFound
        } else {
            e.into()
        }
    })
}

#[cfg(windows)]
fn windows_key_path(scope: &str) -> Result<PathBuf> {
    validate_scope(scope)?;
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or(PackError::SecureStorageUnavailable)?;
    let dir = base.join("openOMSI/protected-keys");
    fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{scope}.dpapi")))
}

#[cfg(windows)]
fn write_windows_key(scope: &str, value: &[u8]) -> Result<()> {
    use std::{io::Write as _, os::windows::ffi::OsStrExt};
    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        },
    };
    let path = windows_key_path(scope)?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    if let Err(e) = f.write_all(value).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(tmp);
        return Err(e.into());
    }
    let source: Vec<u16> = tmp.as_os_str().encode_wide().chain([0]).collect();
    let target: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    if let Err(e) = unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(target.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } {
        let _ = fs::remove_file(tmp);
        return Err(PackError::SecureStorage(e.to_string()));
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows)))]
fn native_store(_: &str, _: &[u8]) -> Result<()> {
    Err(PackError::SecureStorageUnavailable)
}
#[cfg(not(any(target_os = "macos", windows)))]
fn native_load(_: &str) -> Result<Vec<u8>> {
    Err(PackError::SecureStorageUnavailable)
}
#[cfg(not(any(target_os = "macos", windows)))]
fn native_delete(_: &str) -> Result<()> {
    Err(PackError::SecureStorageUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_format_is_lowercase_and_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_trusted_signature_does_not_make_unicode_file_directory_collisions_valid() {
        let root =
            std::env::temp_dir().join(format!("omsi-pack-signed-collision-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let pack = root.join("signed.oopp");
        let signer = SigningKey::generate(&SystemRandom::new()).unwrap();
        let manifest = create_pack(
            &pack,
            PackMetadata {
                publisher_id: "owned-fixture-publisher".into(),
                author: "Fixture".into(),
                pack_id: "collision-fixture".into(),
                version: "1".into(),
                license: "CC0-1.0".into(),
                redistribution: false,
                key_id: None,
                dependencies: Vec::new(),
            },
            &[AssetInput {
                id: "file".into(),
                path: "maps/Café".into(),
                source_sha256: sha256_hex(b"source"),
                bytes: b"a".to_vec(),
            }],
            &signer,
            None,
            &AtomicBool::new(false),
        )
        .unwrap();
        let mut hostile = manifest;
        hostile.assets.push(Asset {
            id: "child".into(),
            path: "maps/Cafe\u{301}/child".into(),
            source_sha256: sha256_hex(b"child source"),
            output_sha256: sha256_hex(b"b"),
            size: 1,
            chunks: Vec::new(),
        });
        let bytes = serde_json::to_vec(&hostile).unwrap();
        fs::write(pack.join("manifest.json"), &bytes).unwrap();
        fs::write(pack.join("manifest.sig"), signer.pair.sign(&bytes).as_ref()).unwrap();
        let mut trusted = TrustedPublishers::default();
        trusted.insert(
            "owned-fixture-publisher",
            signer.key_id(),
            signer.public_key(),
        );
        assert!(load_manifest(&pack, &trusted).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_publisher_file_saves_never_replace_the_winner() {
        use std::sync::{Arc, Barrier};

        let root = std::env::temp_dir().join(format!("omsi-pack-save-race-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("Publishers.json");
        let barrier = Arc::new(Barrier::new(2));
        let writers: Vec<_> = ["publisher-a", "publisher-b"]
            .into_iter()
            .map(|name| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut trusted = TrustedPublishers::default();
                    trusted.insert(name, "00".repeat(32), [0; 32]);
                    write_atomic_after_check(&path, &trusted.to_json().unwrap(), || barrier.wait())
                })
            })
            .collect();
        let successes = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
        let written = TrustedPublishers::load_file(&path).unwrap();
        assert_eq!(written.publishers.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_expired_signed_grant_is_rejected_even_when_already_cached() {
        let root = std::env::temp_dir().join(format!("omsi-pack-expiry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let pack = root.join("expired.oopp");
        let signer = SigningKey::generate(&SystemRandom::new()).unwrap();
        let key = [0x31; 32];
        let manifest = create_pack(
            &pack,
            PackMetadata {
                publisher_id: "expiry-fixture-publisher".into(),
                author: "Fixture".into(),
                pack_id: "expiry-fixture-pack".into(),
                version: "1".into(),
                license: "CC0-1.0".into(),
                redistribution: false,
                key_id: Some(sha256_hex(&key)),
                dependencies: Vec::new(),
            },
            &[AssetInput {
                id: "fixture".into(),
                path: "maps/Fixture/global.cfg".into(),
                source_sha256: sha256_hex(b"source"),
                bytes: b"owned synthetic fixture".to_vec(),
            }],
            &signer,
            Some(&key),
            &AtomicBool::new(false),
        )
        .unwrap();
        let mut trusted = TrustedPublishers::default();
        trusted.insert(
            "expiry-fixture-publisher",
            signer.key_id(),
            signer.public_key(),
        );
        let expires = now_unix().unwrap() + 3600;
        let bytes = issue_entitlement(&manifest, key, expires, &signer).unwrap();
        let mut signed: SignedEntitlement = serde_json::from_slice(&bytes).unwrap();
        signed.entitlement.expires_unix = now_unix().unwrap() - 1;
        let canonical = serde_json::to_vec(&signed.entitlement).unwrap();
        signed.signature = signer.pair.sign(&canonical).as_ref().to_vec();
        let expired = serde_json::to_vec(&signed).unwrap();
        let scope = entitlement_scope(&manifest, &manifest.key_id.clone().unwrap()).unwrap();
        struct Cached {
            scope: String,
            bytes: Vec<u8>,
        }
        impl KeyStore for Cached {
            fn store(&self, _: &str, _: &[u8]) -> Result<()> {
                Ok(())
            }
            fn load(&self, scope: &str) -> Result<Vec<u8>> {
                if scope == self.scope {
                    Ok(self.bytes.clone())
                } else {
                    Err(PackError::KeyNotFound)
                }
            }
            fn delete(&self, _: &str) -> Result<()> {
                Ok(())
            }
        }
        let cached = Cached {
            scope,
            bytes: expired.clone(),
        };
        assert!(matches!(
            VerifiedPack::open_unlocked(&pack, &trusted, &cached),
            Err(PackError::Expired)
        ));
        assert!(matches!(
            unlock(&pack, &expired, &trusted, &cached),
            Err(PackError::Expired)
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
