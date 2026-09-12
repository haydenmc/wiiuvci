# CLAUDE.md

Project guidance for working in this repo. User-facing docs live in `README.md`; this file is about
*how to develop* here.

## What this is

A single-binary Rust reimplementation of the Wii/GameCube → Wii U Virtual Console injection pipeline
(no external `wit`/`nfs2iso2nfs`/`NUSPacker`/`CDecrypt`). See `README.md` for scope and usage.

## Workspace

- `crates/core` — `wiiuvci-core` (all the logic: disc reading, NFS, hash tree, WUP packaging).
- `crates/cli` — `wiiuvci` (the CLI).
- Rust edition 2024, toolchain 1.88+ (the `rust-version` in `Cargo.toml`; the CI MSRV job keeps
  it honest). `crates/core/examples/` holds read-only diagnostic tools (`fst_layout`, `disc_cmp`,
  `recon_disc`, …) — handy oracles when debugging a disc.

## Build & gates (run all three before calling anything done)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features      # keep at 0 warnings
cargo test --workspace --release               # fast tests; needs no fixtures/keys
```

`cargo` is already on `PATH` in this devcontainer (`/usr/local/cargo/bin`); in a fresh shell where
it isn't, `source "$HOME/.cargo/env"` first.

CI (`.github/workflows/ci.yml`) runs the same test suite in **debug** mode (overflow checks catch
real bugs there), not `--release` — the local gate above uses `--release` purely for speed.

## The prime directive: byte-identity

Output must match retail/TeconMoon packages **exactly**. Any change touching the NFS
(`crates/core/src/nfs`, `input.rs::used_data_group_runs`, `disc_patch.rs`) or packaging
(`crates/core/src/package`) must preserve byte-for-byte output unless the change is *intended* to
differ. The standard regression check: build a title with the changed binary **and** with `main` into
two dirs and `cmp` every output file (expect 0 diffs). YDKJ is the fast title for this; Brawl is the
large multi-content / dual-layer stress case.

## Oracle tests (the real correctness proof)

The meaningful validation tests are `#[ignore]`d because they read multi-GB discs and/or need a
secret. Run them manually:

```sh
WIIU_COMMON_KEY=<32-hex> cargo test --workspace --release -- --ignored
```

- **Fixtures:** real disc images in `test_titles/` (git-ignored, not committed). Tests self-skip if a
  title is absent.
- **`WIIU_COMMON_KEY`:** a real secret, passed **only** via env — never write it into code, tests,
  fixtures, or committed files.
- Key oracles: `nfs::tests::nfs_rebuilds_valid_wii_hashes` (sparse NFS round-trips through `nod`'s
  hash validation), `package/content_crypto` retail byte-match, `nfs::tests::zero_trim_shrinks_nfs`.
- Measuring peak RSS: after switching branches, **rebuild before measuring** — a stale
  `target/release/wiiuvci` from another branch will give wrong numbers.

## Architecture map

- `pipeline.rs::run` — top-level orchestration (Wii path); `run_gamecube` for the Nintendont path.
  `Config` is the one options struct; CLI (`crates/cli/src/main.rs`) builds it, inverting `--no-*` /
  opt-in flags into positive fields.
- `input.rs::SourceDisc` — reads the source disc via `nod`; `used_data_group_runs` decides which
  hash groups the NFS stores (FST coverage + gap-skipping + optional zero-fill trimming).
- `disc_patch.rs::plan_disc` — whole-disc hash-tree rebuild plan (H0–H3), in-disc fakesign, `main.dol`
  video patches. Copies the source H3 table verbatim except for edited groups.
- `nfs/` — writes `hif_%06d.nfs` (EGGS header + sparse LBA ranges + per-sector AES), rebuilding the
  Wii hash tree per stored group.
- `package/` — FST, content encryption (hashed H0–H3 tree + non-hashed), TMD/ticket/cert.

Format gotcha worth remembering: a **skipped/trimmed hash group has no stored hash blocks**, so it is
**not hash-valid if read** (a validating reader reports `Invalid H0 hash`). Sparse storage is safe
only because those regions (inter-file gaps, and wholly-zero filler files under `--trim-zeros`) are
never read.

## Git / PR workflow

- The user drives PRs; this environment usually can't push. Only commit/push when asked.
- Branch off `main` for changes; **no merge commits on `main`** (squash/rebase). Keep one focused
  commit per change where practical.
- When asked for a PR, write a `pr-<branch>.md` body file and delete it after the PR is opened/merged.
- Persistent cross-session context (what's merged, hardware-confirmed, known risks) lives in the
  auto-memory under `.claude/projects/.../memory/` — check `MEMORY.md` at the start of a session.
