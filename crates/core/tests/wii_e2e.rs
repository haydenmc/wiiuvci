//! End-to-end Wii disc injection test.
//!
//! Runs the full `pipeline::run` Wii path — decrypt/hash-tree rebuild → NFS → package — using
//! `test_titles/Wii Sports (USA).rvz` and the `.dev/base` staged directory base. Mirrors
//! `gamecube_e2e.rs`'s structure and level of verification. Ignored by default: it needs the
//! local fixtures plus `WIIU_COMMON_KEY`, and reads/writes several GB.
//!
//! Run with:
//! ```sh
//! WIIU_COMMON_KEY=<32-hex> cargo test -p wiiuvci-core --release --test wii_e2e -- --ignored
//! ```

use std::path::Path;

use wiiuvci_core::base::DirBase;
use wiiuvci_core::keys::WiiUCommonKey;
use wiiuvci_core::package::cert::{CertChain, EXPECTED_CERT_LEN};
use wiiuvci_core::pipeline::{self, Config, Region};
use wiiuvci_core::video::VideoPatches;

#[test]
#[ignore = "needs test_titles/Wii Sports (USA).rvz, .dev/base and WIIU_COMMON_KEY; reads/writes several GB"]
fn wii_injection_produces_package_and_rvlt_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("test_titles/Wii Sports (USA).rvz");
    let base_dir = root.join(".dev/base");

    let key_hex = match std::env::var("WIIU_COMMON_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!(
                "skipping wii_injection_produces_package_and_rvlt_files: WIIU_COMMON_KEY not present"
            );
            return;
        }
    };
    for p in [&input, &base_dir] {
        if !p.exists() {
            eprintln!(
                "skipping wii_injection_produces_package_and_rvlt_files: {} not present",
                p.display()
            );
            return;
        }
    }

    let wiiu_common_key = WiiUCommonKey::parse(key_hex.trim().as_bytes()).unwrap();
    // A real `title.cert` lives under `.dev/wup_ref`, which is not present in every dev
    // environment (unlike `.dev/base`); a dummy chain of the right size is fine here since this
    // test doesn't exercise certificate validation. Constructed directly (bypassing
    // `CertChain::from_bytes`'s content checks), matching how `gamecube_e2e.rs` would if it needed
    // to (there, a real cert is available and used instead).
    let cert = CertChain(vec![0u8; EXPECTED_CERT_LEN]);
    let base = DirBase::new(&base_dir).unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("pkg");
    let work = tempfile::tempdir().unwrap();

    let fixed_title = "Wii Sports E2E Test";
    let config = Config {
        input,
        base: Box::new(base),
        out: out.clone(),
        wiiu_common_key,
        cert,
        title: Some(fixed_title.into()),
        icon_png: None,
        boot_tv_png: None,
        boot_drc_png: None,
        region: Region::Usa,
        gamepad: true,
        online: false,
        video: VideoPatches::default(),
        skip_gaps: true,
        trim_zeros: false,
        gamecube: None,
    };

    let summary = pipeline::run(config, work.path()).unwrap();
    assert!(
        summary.package.content_count > 0,
        "package must have contents"
    );
    assert_eq!(summary.title, fixed_title);

    // The output package exists with the expected WUP files.
    assert!(out.join("title.tmd").exists());
    assert!(out.join("title.tik").exists());
    assert!(out.join("title.cert").exists());

    // code/rvlt.tik and code/rvlt.tmd are staged in the work dir, fakesigned: the RSA signature
    // region (0x004..0x104) must be zeroed.
    let tik = std::fs::read(work.path().join("code/rvlt.tik")).unwrap();
    assert!(
        tik[0x004..0x104].iter().all(|&b| b == 0),
        "rvlt.tik signature must be zeroed (fakesigned)"
    );
    let tmd = std::fs::read(work.path().join("code/rvlt.tmd")).unwrap();
    assert!(
        tmd[0x004..0x104].iter().all(|&b| b == 0),
        "rvlt.tmd signature must be zeroed (fakesigned)"
    );

    // meta/meta.xml carries the fixed title.
    let meta_xml = std::fs::read_to_string(work.path().join("meta/meta.xml")).unwrap();
    assert!(
        meta_xml.contains(fixed_title),
        "meta.xml must contain the fixed title {fixed_title:?}"
    );
}
