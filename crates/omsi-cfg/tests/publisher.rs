use omsi_pack::{AssetInput, PackMetadata, SigningKey, TrustedPublishers};
use std::sync::atomic::AtomicBool;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn signed_dependency_reads_through_the_real_vfs_and_cached_provenance_survives_manifest_removal() {
    let _guard = TEST_LOCK.lock().unwrap();
    let root =
        std::env::temp_dir().join(format!("omsi-publisher-integration-{}", std::process::id()));
    std::fs::create_dir_all(root.join("Packs")).unwrap();
    let signer = SigningKey::generate(&ring::rand::SystemRandom::new()).unwrap();
    let mut trust = TrustedPublishers::default();
    trust.insert("fixture", signer.key_id(), signer.public_key());
    trust.save_file(&root.join("Publishers.json")).unwrap();
    let source = "12".repeat(32);
    let metadata = PackMetadata {
        publisher_id: "fixture".into(),
        author: "Fixture".into(),
        pack_id: "scenery".into(),
        version: "1.0.0".into(),
        license: "CC0-1.0".into(),
        redistribution: false,
        key_id: None,
        dependencies: vec![],
    };
    let pack = root.join("Packs/scenery.oopp");
    omsi_pack::create_pack(
        &pack,
        metadata,
        &[AssetInput {
            id: "object".into(),
            path: "Sceneryobjects/Fixture/sign.sco".into(),
            source_sha256: source.clone(),
            bytes: b"[friendlyname]\nOwned fixture\n".to_vec(),
        }],
        &signer,
        None,
        &AtomicBool::new(false),
    )
    .unwrap();
    let catalog = omsi_cfg::publisher::Catalog::load(&root).unwrap();
    let found = catalog.recognize(&source).unwrap();
    assert_eq!(found.dependency.version, "1.0.0");
    assert!(!found.redistribution);
    let mounts = omsi_cfg::publisher::mount_packs(&root).unwrap();
    let object = omsi_cfg::resolve_path(&mounts[0], "Sceneryobjects/Fixture/sign.sco");
    let cfg = omsi_cfg::CfgFile::read(&object).unwrap();
    assert_eq!(cfg.lines[1], "Owned fixture");
    let map = root.join("maps/Fixture");
    std::fs::create_dir_all(&map).unwrap();
    std::fs::write(map.join("dependencies.json"), serde_json::json!({
        "format_version": 1,
        "dependencies": [{"publisher_id":"fixture","pack_id":"scenery","version":"1.0.0"}],
        "assets": [{"path":"Sceneryobjects/Fixture/renamed.sco","dependency":{"publisher_id":"fixture","pack_id":"scenery","version":"1.0.0"},"asset_id":"object"}]
    }).to_string()).unwrap();
    let before = omsi_cfg::content_roots();
    {
        let mounts = omsi_cfg::publisher::validate_map(&map).unwrap();
        assert_eq!(omsi_cfg::content_roots().len(), before.len() + 1);
        let renamed = omsi_cfg::resolve_path(&map, "Sceneryobjects/Fixture/renamed.sco");
        assert_eq!(
            omsi_cfg::CfgFile::read(&renamed).unwrap().lines[1],
            "Owned fixture"
        );
        drop(mounts);
    }
    assert_eq!(omsi_cfg::content_roots(), before);
    std::fs::remove_file(pack.join("manifest.json")).unwrap();
    assert!(
        omsi_cfg::publisher::Catalog::load(&root)
            .unwrap()
            .recognize(&source)
            .is_some()
    );
    for mount in mounts {
        omsi_cfg::vfs::unmount_sealed(&mount);
        omsi_cfg::remove_content_root(&mount);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_map_has_no_compulsory_manifest_and_missing_dependency_is_an_error() {
    let _guard = TEST_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join(format!(
        "omsi-dependency-integration-{}",
        std::process::id()
    ));
    let map = root.join("maps/Fixture");
    std::fs::create_dir_all(&map).unwrap();
    omsi_cfg::publisher::validate_map(&map).unwrap();
    std::fs::write(map.join("dependencies.json"), r#"{"format_version":1,"dependencies":[{"publisher_id":"missing","pack_id":"missing","version":"1.0.0"}],"assets":[]}"#).unwrap();
    omsi_cfg::add_content_root(root.clone());
    assert!(
        omsi_cfg::publisher::validate_map(&map)
            .unwrap_err()
            .to_string()
            .contains("missing")
    );
    omsi_cfg::remove_content_root(&root);
    std::fs::write(map.join("dependencies.json"), r#"{"format_version":1,"dependencies":[{"publisher_id":"missing","pack_id":"missing","version":"1.0.0"}],"assets":[{"path":"Plugins/evil.lua","dependency":{"publisher_id":"missing","pack_id":"missing","version":"1.0.0"},"asset_id":"missing"}]}"#).unwrap();
    omsi_cfg::add_content_root(root.clone());
    let before = omsi_cfg::content_roots();
    assert!(omsi_cfg::publisher::validate_map(&map).is_err());
    assert_eq!(omsi_cfg::content_roots(), before);
    omsi_cfg::remove_content_root(&root);
    std::fs::remove_dir_all(root).unwrap();
}
