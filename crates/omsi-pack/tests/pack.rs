use std::sync::atomic::AtomicBool;

use omsi_pack::{create_pack, AssetInput, Dependency, PackMetadata, SigningKey, TrustedPublishers, VerifiedPack};
use ring::rand::SystemRandom;

fn scratch() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("omsi-pack-test-{}", std::process::id()))
}

fn metadata() -> PackMetadata {
    PackMetadata {
        publisher_id: "owned-fixture-publisher".into(),
        author: "Fixture Author".into(),
        pack_id: "owned-fixture-pack".into(),
        version: "1.0.0".into(),
        license: "CC0-1.0".into(),
        redistribution: false,
        key_id: Some("owned-fixture-key".into()),
        dependencies: vec![Dependency {
            publisher_id: "other-publisher".into(),
            pack_id: "shared-dependency".into(),
            version: "2.1.0".into(),
        }],
    }
}

#[test]
fn trusted_signed_encrypted_pack_round_trips_bounded_assets() {
    let root = scratch();
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("pack.oopp");
    let signer = SigningKey::generate(&SystemRandom::new()).unwrap();
    let mut trust = TrustedPublishers::default();
    trust.insert("owned-fixture-publisher", signer.key_id(), signer.public_key());
    let key = [0x5a; 32];
    let bytes = b"synthetic map bytes".to_vec();
    let source_hash = format!("{:x}", sha2::Sha256::digest(b"original source bytes"));
    let manifest = create_pack(
        &out,
        metadata(),
        &[AssetInput { path: "maps/Test/global.cfg".into(), source_hash, bytes: bytes.clone() }],
        &signer,
        Some(&key),
        &AtomicBool::new(false),
    ).unwrap();
    assert_eq!(manifest.dependencies[0].version, "2.1.0");
    assert!(!std::fs::read(out.join("manifest.json")).unwrap().windows(bytes.len()).any(|w| w == bytes));

    let pack = VerifiedPack::open(&out, &trust, Some(key)).unwrap();
    assert_eq!(pack.read("maps/Test/global.cfg").unwrap(), bytes);
    assert_eq!(pack.assets().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_signer_wrong_key_tampering_and_traversal_fail_closed() {
    let root = scratch();
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("pack.oopp");
    let signer = SigningKey::generate(&SystemRandom::new()).unwrap();
    let trust = TrustedPublishers::default();
    let source_hash = format!("{:x}", sha2::Sha256::digest(b"original"));
    create_pack(
        &out,
        metadata(),
        &[AssetInput { path: "maps/Test/global.cfg".into(), source_hash, bytes: b"fixture".to_vec() }],
        &signer,
        Some(&[0x12; 32]),
        &AtomicBool::new(false),
    ).unwrap();
    assert!(VerifiedPack::open(&out, &trust, Some([0x12; 32])).is_err());
    let mut trusted = TrustedPublishers::default();
    trusted.insert("owned-fixture-publisher", signer.key_id(), signer.public_key());
    assert!(VerifiedPack::open(&out, &trusted, Some([0x34; 32])).unwrap().read("maps/Test/global.cfg").is_err());

    let manifest = VerifiedPack::open(&out, &trusted, Some([0x12; 32])).unwrap().manifest().clone();
    let chunk = &manifest.assets[0].chunks[0].file;
    let mut bytes = std::fs::read(out.join(chunk)).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(out.join(chunk), bytes).unwrap();
    assert!(VerifiedPack::open(&out, &trusted, Some([0x12; 32])).unwrap().read("maps/Test/global.cfg").is_err());

    let bad = root.join("traversal.oopp");
    assert!(create_pack(
        &bad,
        metadata(),
        &[AssetInput { path: "../escape.txt".into(), source_hash: "00".repeat(32), bytes: b"x".to_vec() }],
        &signer,
        None,
        &AtomicBool::new(false),
    ).is_err());
    assert!(!bad.exists());
    std::fs::remove_dir_all(root).unwrap();
}

use sha2::Digest;
