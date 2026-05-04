//! PDF *reader* — byte-stream → typed object tree → high-level Scene.
//!
//! Round 3, in commits:
//!
//! 1. [`lex`]: tokenizer (bytes → [`Token`]s) per ISO 32000-1 §7.2.
//! 2. [`parse`]: object parser (tokens → [`crate::objects::Object`]).
//! 3. xref + trailer parser, top-level catalog walk.
//! 4. Content-stream operator parser (inverse of
//!    [`crate::operators`]) — `m`/`l`/`c`/`re` → [`PathCommand`],
//!    `cm` → [`Transform2D`], `q`/`Q` → group save/restore, etc.
//! 5. /Info dict → [`oxideav_scene::Metadata`] +
//!    Scene assembly via [`oxideav_scene::Page`].
//!
//! Round 3 supports PDF 1.4 with simple xref + uncompressed object
//! streams. Object streams (PDF 1.5+), encryption, incremental
//! updates, and linearization land in round 4+.
//!
//! [`Token`]: lex::Token
//! [`PathCommand`]: oxideav_core::vector::PathCommand
//! [`Transform2D`]: oxideav_core::vector::Transform2D

pub mod content;
pub mod lex;
pub mod parse;
pub mod xref;
