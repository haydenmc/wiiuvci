//! Numeric constants for the Wii partition / hash-tree layout, shared by [`crate::disc_patch`],
//! [`crate::nfs`], [`crate::wii_author`], [`crate::input`] and the TMD/ticket fakesign patching
//! in [`crate::pipeline`].
//!
//! Before this module existed, each value below was independently declared (under a few
//! different names) in two to four of those files. Consolidating them here is a pure
//! deduplication — every value is unchanged from before.

/// Clusters per Wii hash group: 64 clusters share one `H3` table entry.
pub(crate) const SECTORS_PER_GROUP: usize = 64;

/// Size of a cluster's hash block (the `H0`/`H1`/`H2` sub-tables) at the start of every 0x8000
/// cluster.
pub(crate) const HASH_BLOCK: usize = 0x400;

/// Bytes of real (non-hash) data per cluster: the 0x8000 cluster minus its [`HASH_BLOCK`].
pub(crate) const CLUSTER_DATA: usize = crate::input::DISC_SECTOR_SIZE - HASH_BLOCK; // 0x7C00

/// `u64` form of [`CLUSTER_DATA`], so the logical byte-offset arithmetic in [`crate::input`] and
/// [`crate::nfs`] — which is all `u64` — reads without a cast at every use.
pub(crate) const CLUSTER_DATA_U64: u64 = CLUSTER_DATA as u64;

/// `u64` form of [`SECTORS_PER_GROUP`], for the same reason as [`CLUSTER_DATA_U64`].
pub(crate) const SECTORS_PER_GROUP_U64: u64 = SECTORS_PER_GROUP as u64;

/// Size of one `H0` sub-block: the unit the `H0` table hashes.
pub(crate) const SUBBLOCK: usize = 0x400;

/// Sub-blocks of data per cluster (`CLUSTER_DATA / SUBBLOCK`), i.e. the number of `H0` hashes.
pub(crate) const N_SUBBLOCKS: usize = 31;

/// Clusters per hash subgroup: 8 clusters share one `H1` table, 8 subgroups make a
/// [`SECTORS_PER_GROUP`]-cluster group.
pub(crate) const SECTORS_PER_SUBGROUP: usize = 8;

/// The `H0` region at the start of a cluster's hash block: [`N_SUBBLOCKS`] SHA-1s (`0x000..0x26C`).
/// `H1[s] = SHA1(cluster s's H0 region)`.
pub(crate) const H0_REGION: usize = N_SUBBLOCKS * 20; // 0x26C

/// Offset of the subgroup's `H1` table within a cluster's hash block.
pub(crate) const H1_OFF: usize = 0x280;

/// Size of an `H1` table: one SHA-1 per cluster in the subgroup (`0xA0`).
/// `H2[g] = SHA1(subgroup g's H1 region)`.
pub(crate) const H1_REGION: usize = SECTORS_PER_SUBGROUP * 20; // 0xA0

/// Offset of the group's `H2` table within a cluster's hash block.
pub(crate) const H2_OFF: usize = 0x340;

/// Size of an `H2` table: one SHA-1 per subgroup in the group (`0xA0`).
/// `H3[group] = SHA1(the group's H2 region)`.
pub(crate) const H2_REGION: usize = (SECTORS_PER_GROUP / SECTORS_PER_SUBGROUP) * 20; // 0xA0

/// Offset of the Wii TMD's single content-record hash (a 20-byte SHA-1) within the TMD.
pub(crate) const TMD_CONTENT0_HASH: usize = 0x1F4;

/// The RSA-2048 signature region of a Wii ticket/TMD (`0x004..0x104`), zeroed to fakesign it.
pub(crate) const WII_SIG: std::ops::Range<usize> = 0x004..0x104;
