//! Wii U title metadata: identifier derivation and `code/app.xml` / `meta/meta.xml` generation.

pub mod appxml;
pub mod metaxml;
pub mod titleid;

pub use appxml::generate as generate_app_xml;
pub use metaxml::{MetaOptions, patch as patch_meta_xml};
pub use titleid::{TitleIds, derive as derive_title_ids};
