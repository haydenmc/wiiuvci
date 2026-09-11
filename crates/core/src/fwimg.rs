//! Byte-pattern patches for the base title's `fw.img` (the vWii firmware image).
//!
//! A fakesigned title needs `fw.img`'s signature check neutered; a title that boots **homebrew**
//! (Nintendont, for GameCube injection) additionally needs AHBPROT and MEMPROT disabled so the
//! loaded DOL gets full hardware access. Each patch is a search-and-replace that is applied only
//! where its signature is found and skipped otherwise — the exact bytes vary by base title and
//! firmware version, so a missing pattern must never corrupt the image.
//!
//! Patches are organized into **groups** (e.g. `fakesign`). A group can have several alternative
//! signatures — bases differ in which they use — and matching *any* member satisfies it. We only
//! warn when a whole group goes unmatched; an individual alternative that does not match is normal
//! and logged at `debug`.
//!
//! The patterns mirror the Wii-VC homebrew patches used by `nfs2iso2nfs`/UWUVCI. They cannot be
//! verified in this repository (there is no `fw.img` fixture, and the effect is only observable on
//! hardware); they are applied defensively and logged.

use std::path::Path;

use crate::error::{Error, Result};

/// A single search-and-replace patch against `fw.img`.
pub struct BytePatch {
    /// Human-readable name for logging.
    pub name: &'static str,
    /// Logical patch this belongs to; alternatives share a group, and matching any one member
    /// satisfies the group.
    pub group: &'static str,
    /// Byte signature to locate.
    pub find: &'static [u8],
    /// Offset within a match at which to write [`Self::write`].
    pub at: usize,
    /// Replacement bytes.
    pub write: &'static [u8],
    /// Apply at every match (`true`) or only the first (`false`).
    pub all: bool,
}

/// Fakesign patch: neuter the signature check (`20 07 23 A2` / `20 07 4B 0B` → set the following
/// byte to 0). Both are variants of the same logical `fakesign` patch; bases use one or the other.
pub const FAKESIGN_A: BytePatch = BytePatch {
    name: "fakesign",
    group: "fakesign",
    find: &[0x20, 0x07, 0x23, 0xA2],
    at: 1,
    write: &[0x00],
    all: true,
};
pub const FAKESIGN_B: BytePatch = BytePatch {
    name: "fakesign(alt)",
    group: "fakesign",
    find: &[0x20, 0x07, 0x4B, 0x0B],
    at: 1,
    write: &[0x00],
    all: true,
};

/// Disable AHBPROT so homebrew gets full hardware access (`D0 0B 23 08 43 13 60 0B` → `46 C0`).
pub const AHBPROT: BytePatch = BytePatch {
    name: "AHBPROT-disable",
    group: "AHBPROT",
    find: &[0xD0, 0x0B, 0x23, 0x08, 0x43, 0x13, 0x60, 0x0B],
    at: 0,
    write: &[0x46, 0xC0],
    all: false,
};

/// Disable MEMPROT (`01 94 B5 00 4B 08 22 01` → the trailing `22 01` becomes `22 00`).
pub const MEMPROT: BytePatch = BytePatch {
    name: "MEMPROT-disable",
    group: "MEMPROT",
    find: &[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01],
    at: 6,
    write: &[0x22, 0x00],
    all: false,
};

// Controller-input patches for a homebrew (Nintendont) title, matching `nfs2iso2nfs`'s
// `-homebrew` + `-passthrough` sets (which TeconMoon/gc-wiiu-injector apply for GameCube injects).
// These are NOT boot/signature patches — the boot-critical ones are fakesign/AHBPROT/MEMPROT
// above. `-passthrough` ([`PASSTHROUGH_1`]–[`PASSTHROUGH_3`]) lets homebrew keep using real Wii
// Remotes; the three Nintendont patches ([`NINTENDONT_1`]–[`NINTENDONT_3`], part of `-homebrew`)
// enable proper input support in Nintendont. Byte patterns taken from FIX94's `nfs2iso2nfs`
// (Program.cs); with all six applied our patched `fw.img` reproduces a known-good TeconMoon
// inject's byte-for-byte. Each pattern is unique in the reference base; a base lacking one is a
// no-op.

/// `-passthrough` #1: `20 4B 01 68 18 47 70 00` → `20 00` at +3 (here matched with leading context).
pub const PASSTHROUGH_1: BytePatch = BytePatch {
    name: "wiimote-passthrough-1",
    group: "wiimote-passthrough-1",
    find: &[
        0x13, 0x8B, 0xB0, 0x20, 0x4B, 0x01, 0x68, 0x18, 0x47, 0x70, 0x00, 0x00, 0x13, 0x8B,
    ],
    at: 6,
    write: &[0x20, 0x00],
    all: false,
};
/// `-passthrough` #2: branch to the passthrough helper (`28 00 D0 03 49 02 22 09` site).
pub const PASSTHROUGH_2: BytePatch = BytePatch {
    name: "wiimote-passthrough-2",
    group: "wiimote-passthrough-2",
    find: &[
        0x13, 0x8B, 0xB0, 0x68, 0xB5, 0x00, 0x28, 0x00, 0xD0, 0x03, 0x49, 0x02, 0x22, 0x09, 0xF0,
        0x04, 0xFF, 0x1D, 0xBD, 0x00, 0x13, 0x8B, 0xA0, 0x04,
    ],
    at: 6,
    write: &[
        0xF0, 0x04, 0xFF, 0x21, 0x48, 0x02, 0x21, 0x09, 0xF0, 0x04, 0xFE, 0xF9,
    ],
    all: false,
};
/// `-passthrough` #3: `F0 01 FA B9` → `F7 FC FB 95` (retarget a `bl`).
pub const PASSTHROUGH_3: BytePatch = BytePatch {
    name: "wiimote-passthrough-3",
    group: "wiimote-passthrough-3",
    find: &[
        0x1C, 0x28, 0x46, 0x69, 0x22, 0x09, 0xF0, 0x01, 0xFA, 0xB9, 0x20, 0x00, 0xE7, 0xBE, 0x78,
        0x63,
    ],
    at: 6,
    write: &[0xF7, 0xFC, 0xFB, 0x95],
    all: false,
};
/// Nintendont input patch #1 (`B0 BA 1C 0F` site): splice an ARM code hook.
pub const NINTENDONT_1: BytePatch = BytePatch {
    name: "nintendont-1",
    group: "nintendont-1",
    find: &[
        0xFB, 0xF8, 0xFF, 0xFF, 0xFB, 0xF6, 0xB5, 0xF0, 0x46, 0x5F, 0x46, 0x56, 0x46, 0x4D, 0x46,
        0x44, 0xB4, 0xF0, 0xB0, 0xBA, 0x1C, 0x0F, 0x1C, 0x15, 0x93, 0x18, 0x24, 0x00,
    ],
    at: 6,
    write: &[
        0xE5, 0x9F, 0x10, 0x04, 0xE5, 0x91, 0x00, 0x00, 0xE1, 0x2F, 0xFF, 0x10, 0x12, 0xFF, 0xFF,
        0xE0,
    ],
    all: false,
};
/// Nintendont input patch #2 (`68 4B 2B 06` site): splice a THUMB code hook.
pub const NINTENDONT_2: BytePatch = BytePatch {
    name: "nintendont-2",
    group: "nintendont-2",
    find: &[
        0xF8, 0xF2, 0xF0, 0x00, 0xFF, 0x4E, 0x68, 0x4B, 0x2B, 0x06, 0xD1, 0x0C, 0x68, 0x8B, 0x2B,
        0x00, 0xD1, 0x09, 0x68, 0xC8, 0x68, 0x42, 0x23, 0xA9, 0x00, 0x9B, 0x42, 0x9A, 0xD1, 0x03,
        0x69, 0x02,
    ],
    at: 6,
    write: &[
        0x49, 0x01, 0x47, 0x88, 0x46, 0xC0, 0xE0, 0x01, 0x12, 0xFF, 0xFE, 0x00, 0x22, 0x00, 0x23,
        0x01, 0x46, 0xC0, 0x46, 0xC0,
    ],
    all: false,
};
/// Nintendont input patch #3: flips the byte after the `0D 80 00 00` marker (`02` → `03`).
pub const NINTENDONT_3: BytePatch = BytePatch {
    name: "nintendont-3",
    group: "nintendont-3",
    find: &[
        0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
    ],
    at: 6,
    write: &[0x03],
    all: false,
};

/// The patch set for an ordinary (Wii) fakesigned title: both fakesign signature variants.
/// Bases differ in which one they use — Rhythm Heaven Fever, for instance, uses the `20 07 4B 0B`
/// variant — so we try both; a missing one is a no-op.
pub const FAKESIGN_PATCHES: &[BytePatch] = &[FAKESIGN_A, FAKESIGN_B];

/// The patch set for a homebrew-booting (Nintendont) title: the boot-critical fakesign + AHBPROT +
/// MEMPROT patches plus the Wii-Remote-passthrough and Nintendont controller-input patches
/// (`nfs2iso2nfs` `-homebrew`/`-passthrough`).
pub const HOMEBREW_PATCHES: &[BytePatch] = &[
    FAKESIGN_A,
    FAKESIGN_B,
    AHBPROT,
    MEMPROT,
    PASSTHROUGH_1,
    PASSTHROUGH_2,
    PASSTHROUGH_3,
    NINTENDONT_1,
    NINTENDONT_2,
    NINTENDONT_3,
];

/// Apply `patches` to `data` in place, returning the names of the patches that matched. A patch
/// whose signature is absent is skipped (and logged at `debug`); deciding what a *missing* patch
/// means is left to the caller / [`unmatched_groups`], since alternatives share a group.
pub fn apply_patches(data: &mut [u8], patches: &[BytePatch]) -> Vec<&'static str> {
    let mut applied = Vec::new();
    for p in patches {
        let mut hits = 0usize;
        let mut i = 0usize;
        while i + p.find.len() <= data.len() {
            if &data[i..i + p.find.len()] == p.find {
                let dst = i + p.at;
                data[dst..dst + p.write.len()].copy_from_slice(p.write);
                hits += 1;
                if !p.all {
                    break;
                }
                i += p.find.len();
            } else {
                i += 1;
            }
        }
        if hits > 0 {
            applied.push(p.name);
        } else {
            log::debug!("fw.img: variant '{}' not present; skipped", p.name);
        }
    }
    applied
}

/// The groups in `patches` for which no member matched (`applied` is the output of
/// [`apply_patches`]). These are the genuinely noteworthy misses — an unmatched group means a
/// capability could not be patched at all.
pub fn unmatched_groups<'a>(patches: &'a [BytePatch], applied: &[&str]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for p in patches {
        let satisfied = patches
            .iter()
            .any(|q| q.group == p.group && applied.contains(&q.name));
        if !satisfied && !out.contains(&p.group) {
            out.push(p.group);
        }
    }
    out
}

/// Read `path`, apply `patches`, and write it back. Logs the applied patches at `info` and warns
/// once per patch *group* that matched nothing. A title with no matching patterns is left
/// byte-identical.
pub fn patch_file(path: &Path, patches: &[BytePatch]) -> Result<Vec<&'static str>> {
    let mut data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    let applied = apply_patches(&mut data, patches);
    if !applied.is_empty() {
        std::fs::write(path, &data).map_err(|e| Error::io(path, e))?;
        log::info!("patched fw.img: {}", applied.join(", "));
    }
    for group in unmatched_groups(patches, &applied) {
        log::warn!("fw.img: no '{group}' patch site found; title may not load without it");
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fakesign_patches_every_site() {
        let mut data = vec![0u8; 32];
        data[4..8].copy_from_slice(&[0x20, 0x07, 0x23, 0xA2]);
        data[20..24].copy_from_slice(&[0x20, 0x07, 0x23, 0xA2]);
        let applied = apply_patches(&mut data, &[FAKESIGN_A]);
        assert_eq!(applied, vec!["fakesign"]);
        assert_eq!(data[5], 0x00);
        assert_eq!(data[21], 0x00);
    }

    #[test]
    fn ahbprot_replaces_first_two_bytes_of_match() {
        let mut data = vec![0xFFu8; 16];
        data[3..11].copy_from_slice(&[0xD0, 0x0B, 0x23, 0x08, 0x43, 0x13, 0x60, 0x0B]);
        let applied = apply_patches(&mut data, &[AHBPROT]);
        assert_eq!(applied, vec!["AHBPROT-disable"]);
        assert_eq!(&data[3..5], &[0x46, 0xC0]);
        // The rest of the matched region is untouched.
        assert_eq!(&data[5..11], &[0x23, 0x08, 0x43, 0x13, 0x60, 0x0B]);
    }

    #[test]
    fn memprot_clears_trailing_flag() {
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01]);
        let applied = apply_patches(&mut data, &[MEMPROT]);
        assert_eq!(applied, vec!["MEMPROT-disable"]);
        assert_eq!(&data[6..8], &[0x22, 0x00]);
    }

    #[test]
    fn missing_pattern_is_skipped_not_applied() {
        let mut data = vec![0u8; 16];
        let applied = apply_patches(&mut data, &[AHBPROT]);
        assert!(applied.is_empty());
        assert_eq!(data, vec![0u8; 16], "no bytes changed when pattern absent");
    }

    #[test]
    fn matched_alternate_satisfies_the_fakesign_group() {
        // Only the `20 07 4B 0B` variant is present (as in the Rhythm Heaven Fever base).
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&[0x20, 0x07, 0x4B, 0x0B]);
        let applied = apply_patches(&mut data, FAKESIGN_PATCHES);
        assert_eq!(applied, vec!["fakesign(alt)"]);
        // The group is satisfied, so nothing to warn about even though variant A didn't match.
        assert!(
            unmatched_groups(FAKESIGN_PATCHES, &applied).is_empty(),
            "a matched alternate must satisfy the fakesign group"
        );
    }

    #[test]
    fn fully_unmatched_group_is_reported() {
        let mut data = vec![0u8; 16]; // no signatures present
        let applied = apply_patches(&mut data, HOMEBREW_PATCHES);
        assert!(applied.is_empty());
        // Each logical group is reported exactly once, not once per variant.
        assert_eq!(
            unmatched_groups(HOMEBREW_PATCHES, &applied),
            vec![
                "fakesign",
                "AHBPROT",
                "MEMPROT",
                "wiimote-passthrough-1",
                "wiimote-passthrough-2",
                "wiimote-passthrough-3",
                "nintendont-1",
                "nintendont-2",
                "nintendont-3",
            ]
        );
    }

    /// Against a real staged base `fw.img`, the Wii fakesign group must be satisfied (Rhythm Heaven
    /// Fever uses the `20 07 4B 0B` variant at 0x271EE). Guards the regression where only the
    /// `20 07 23 A2` variant was checked and a warning fired on a patchable base.
    #[test]
    #[ignore = "needs .dev/base/code/fw.img"]
    fn patches_real_base_fwimg() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/base/code/fw.img");
        if !path.exists() {
            eprintln!(
                "skipping patches_real_base_fwimg: {} not present",
                path.display()
            );
            return;
        }
        let mut data = std::fs::read(&path).unwrap();
        let applied = apply_patches(&mut data, FAKESIGN_PATCHES);
        assert!(
            !applied.is_empty(),
            "a real base fw.img must match at least one fakesign variant, got {applied:?}"
        );
        assert!(
            unmatched_groups(FAKESIGN_PATCHES, &applied).is_empty(),
            "the fakesign group must be satisfied on a real base"
        );
    }

    #[test]
    fn first_match_only_when_not_all() {
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01]);
        data[16..24].copy_from_slice(&[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01]);
        apply_patches(&mut data, &[MEMPROT]);
        assert_eq!(&data[6..8], &[0x22, 0x00], "first match patched");
        assert_eq!(&data[22..24], &[0x22, 0x01], "second match left alone");
    }
}
