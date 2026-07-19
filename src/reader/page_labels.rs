//! Round-418 — **page labels** reader (ISO 32000-1 §12.4.2).
//!
//! A document may label its pages independently of their 0-based
//! indices: the catalogue's `/PageLabels` entry is a number tree
//! (§7.9.7) whose keys are the page index starting each *labelling
//! range* and whose values are page label dictionaries (Table 159):
//!
//! * `/S` — numbering style for the numeric portion: `D` decimal,
//!   `R` / `r` upper / lower Roman numerals, `A` / `a` upper / lower
//!   letters (A–Z, then AA–ZZ, …). No `/S` ⇒ no numeric portion.
//! * `/P` — a text-string prefix for every label in the range.
//! * `/St` — the numeric value of the range's first page (≥ 1 per the
//!   spec; default 1).
//!
//! [`page_label_ranges`] surfaces the raw ranges; [`page_labels`]
//! synthesises the per-page label strings the ranges denote — the
//! §12.4.2 example `<< /Nums [0 <</S /r>> 4 <</S /D>> 7 <</S /D /P
//! (A-) /St 8>>] >>` yields `i, ii, iii, iv, 1, 2, 3, A-8, A-9, …`.
//!
//! Tolerances (each documented at the point of use): a tree missing
//! the required index-0 entry labels the uncovered leading pages with
//! their 1-based decimal position (the same text a viewer shows for a
//! document with no `/PageLabels` at all); an out-of-spec `/St` < 1
//! clamps to 1; Roman/letter values are generated for values ≥ 1.

use std::collections::HashMap;

use crate::error::PdfError;
use crate::objects::{Dict, Object};
use crate::reader::document::DocumentReader;
use crate::reader::nametree::number_tree_entries;
use crate::reader::outline::build_page_index_map;

/// `/S` numbering style (Table 159).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLabelStyle {
    /// `D` — decimal arabic numerals.
    Decimal,
    /// `R` — uppercase Roman numerals.
    RomanUpper,
    /// `r` — lowercase Roman numerals.
    RomanLower,
    /// `A` — uppercase letters (A–Z, AA–ZZ, …).
    AlphaUpper,
    /// `a` — lowercase letters (a–z, aa–zz, …).
    AlphaLower,
}

impl PageLabelStyle {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "D" => Some(Self::Decimal),
            "R" => Some(Self::RomanUpper),
            "r" => Some(Self::RomanLower),
            "A" => Some(Self::AlphaUpper),
            "a" => Some(Self::AlphaLower),
            // Unknown style name — Table 159 enumerates exactly five;
            // treat anything else as "no numeric portion" (None).
            _ => None,
        }
    }
}

/// One labelling range — a `/PageLabels` number-tree entry (Table
/// 159) with its starting page index.
#[derive(Debug, Clone, PartialEq)]
pub struct PageLabelRange {
    /// Page index (0-based) of the first page in the range — the
    /// number-tree key.
    pub start_index: i64,
    /// `/S` numbering style; `None` when the label is prefix-only.
    pub style: Option<PageLabelStyle>,
    /// `/P` label prefix (decoded text string); empty when absent.
    pub prefix: String,
    /// `/St` — numeric value of the first label in the range.
    /// Defaults to 1; an out-of-spec value < 1 is clamped to 1.
    pub start_value: i64,
}

impl PageLabelRange {
    /// The label of the page `offset` pages into this range.
    pub fn label_at(&self, offset: i64) -> String {
        let mut out = self.prefix.clone();
        if let Some(style) = self.style {
            let value = self.start_value.saturating_add(offset);
            out.push_str(&numeric_portion(style, value));
        }
        out
    }
}

/// Read the catalogue's `/PageLabels` number tree into its ranges,
/// sorted by starting page index. `Ok(None)` when the catalogue has
/// no `/PageLabels` entry (the common case — pages are then labelled
/// by 1-based position, by convention).
pub fn page_label_ranges(
    reader: &mut DocumentReader<'_>,
) -> Result<Option<Vec<PageLabelRange>>, PdfError> {
    let root_id = reader.xref().root()?;
    let catalog = reader.resolve(root_id)?;
    let Object::Dict(catalog_dict) = catalog else {
        return Ok(None);
    };
    let labels_obj = catalog_dict
        .entries()
        .iter()
        .find(|(k, _)| k == "PageLabels")
        .map(|(_, v)| v.clone());
    let Some(labels_obj) = labels_obj else {
        return Ok(None);
    };
    let tree_root = match reader.deref(labels_obj)? {
        Object::Dict(d) => d,
        _ => return Ok(None),
    };
    let entries = number_tree_entries(reader, &tree_root)?;
    let mut ranges: Vec<PageLabelRange> = Vec::with_capacity(entries.len());
    for (start_index, value) in entries {
        if start_index < 0 {
            // A negative page index is meaningless — skip.
            continue;
        }
        let dict = match reader.deref(value)? {
            Object::Dict(d) => d,
            // Table 159 requires a dictionary value; skip others.
            _ => continue,
        };
        ranges.push(range_from_dict(start_index, &dict));
    }
    ranges.sort_by_key(|r| r.start_index);
    ranges.dedup_by_key(|r| r.start_index);
    Ok(Some(ranges))
}

/// Synthesise the per-page label strings — one `String` per page in
/// `/Pages`-tree DFS order. `Ok(None)` when the document defines no
/// `/PageLabels`.
pub fn page_labels(reader: &mut DocumentReader<'_>) -> Result<Option<Vec<String>>, PdfError> {
    let Some(ranges) = page_label_ranges(reader)? else {
        return Ok(None);
    };
    let page_count = build_page_index_map(reader)?.len();
    Ok(Some(labels_for_pages(&ranges, page_count)))
}

/// Apply sorted `ranges` to `page_count` pages. Pages before the
/// first range (a tree missing the required index-0 entry) are
/// labelled with their 1-based decimal position — the text a viewer
/// shows when no labelling applies at all.
pub(crate) fn labels_for_pages(ranges: &[PageLabelRange], page_count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(page_count);
    let mut cur: Option<&PageLabelRange> = None;
    let mut next = ranges.iter().peekable();
    for index in 0..page_count as i64 {
        while let Some(r) = next.peek() {
            if r.start_index <= index {
                cur = Some(next.next().expect("peeked"));
            } else {
                break;
            }
        }
        match cur {
            Some(r) => out.push(r.label_at(index - r.start_index)),
            None => out.push((index + 1).to_string()),
        }
    }
    out
}

fn range_from_dict(start_index: i64, dict: &Dict) -> PageLabelRange {
    let style = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "S")
        .and_then(|(_, v)| match v {
            Object::Name(s) => PageLabelStyle::from_name(s),
            _ => None,
        });
    let prefix = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "P")
        .and_then(|(_, v)| match v {
            Object::LiteralString(b) | Object::HexString(b) => {
                Some(crate::reader::nametree::decode_key_text(b))
            }
            _ => None,
        })
        .unwrap_or_default();
    let start_value = dict
        .entries()
        .iter()
        .find(|(k, _)| k == "St")
        .and_then(|(_, v)| match v {
            Object::Integer(n) => Some(*n),
            _ => None,
        })
        // Table 159: "shall be greater than or equal to 1. Default
        // value: 1." — clamp out-of-spec values up to 1.
        .map(|n| n.max(1))
        .unwrap_or(1);
    PageLabelRange {
        start_index,
        style,
        prefix,
        start_value,
    }
}

/// The numeric portion of a label for `value` under `style`.
fn numeric_portion(style: PageLabelStyle, value: i64) -> String {
    match style {
        PageLabelStyle::Decimal => value.to_string(),
        PageLabelStyle::RomanUpper => roman(value),
        PageLabelStyle::RomanLower => roman(value).to_lowercase(),
        PageLabelStyle::AlphaUpper => alpha(value, b'A'),
        PageLabelStyle::AlphaLower => alpha(value, b'a'),
    }
}

/// Standard-form (subtractive) Roman numerals. Roman numerals denote
/// positive integers only; a value < 1 (unreachable through the
/// clamped `/St`, but defensive) falls back to decimal.
fn roman(value: i64) -> String {
    if value < 1 {
        return value.to_string();
    }
    const TABLE: [(i64, &str); 13] = [
        (1000, "M"),
        (900, "CM"),
        (500, "D"),
        (400, "CD"),
        (100, "C"),
        (90, "XC"),
        (50, "L"),
        (40, "XL"),
        (10, "X"),
        (9, "IX"),
        (5, "V"),
        (4, "IV"),
        (1, "I"),
    ];
    let mut n = value;
    let mut out = String::new();
    for (weight, glyphs) in TABLE {
        while n >= weight {
            out.push_str(glyphs);
            n -= weight;
        }
    }
    out
}

/// Letter numbering per Table 159: "A to Z for the first 26 pages,
/// AA to ZZ for the next 26, and so on" — value `n` is the letter
/// `(n−1) mod 26` repeated `⌈n / 26⌉` times.
fn alpha(value: i64, base: u8) -> String {
    if value < 1 {
        return value.to_string();
    }
    let letter = (base + ((value - 1) % 26) as u8) as char;
    let repeats = ((value - 1) / 26 + 1) as usize;
    let mut out = String::with_capacity(repeats);
    for _ in 0..repeats {
        out.push(letter);
    }
    out
}

/// Convenience: `page-index → label` map form of [`page_labels`],
/// for callers that address pages sparsely.
pub fn page_label_map(
    reader: &mut DocumentReader<'_>,
) -> Result<Option<HashMap<usize, String>>, PdfError> {
    Ok(page_labels(reader)?.map(|v| v.into_iter().enumerate().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roman_standard_form() {
        assert_eq!(roman(1), "I");
        assert_eq!(roman(4), "IV");
        assert_eq!(roman(9), "IX");
        assert_eq!(roman(14), "XIV");
        assert_eq!(roman(40), "XL");
        assert_eq!(roman(90), "XC");
        assert_eq!(roman(400), "CD");
        assert_eq!(roman(1990), "MCMXC");
        assert_eq!(roman(2026), "MMXXVI");
        assert_eq!(roman(3999), "MMMCMXCIX");
    }

    #[test]
    fn alpha_repeats_beyond_z() {
        assert_eq!(alpha(1, b'A'), "A");
        assert_eq!(alpha(26, b'A'), "Z");
        assert_eq!(alpha(27, b'A'), "AA");
        assert_eq!(alpha(52, b'A'), "ZZ");
        assert_eq!(alpha(53, b'A'), "AAA");
        assert_eq!(alpha(2, b'a'), "b");
    }

    #[test]
    fn spec_example_labels() {
        // §12.4.2 EXAMPLE: i, ii, iii, iv, 1, 2, 3, A-8, A-9, …
        let ranges = vec![
            PageLabelRange {
                start_index: 0,
                style: Some(PageLabelStyle::RomanLower),
                prefix: String::new(),
                start_value: 1,
            },
            PageLabelRange {
                start_index: 4,
                style: Some(PageLabelStyle::Decimal),
                prefix: String::new(),
                start_value: 1,
            },
            PageLabelRange {
                start_index: 7,
                style: Some(PageLabelStyle::Decimal),
                prefix: "A-".into(),
                start_value: 8,
            },
        ];
        let labels = labels_for_pages(&ranges, 9);
        assert_eq!(
            labels,
            vec!["i", "ii", "iii", "iv", "1", "2", "3", "A-8", "A-9"]
        );
    }

    #[test]
    fn prefix_only_and_missing_zero_entry() {
        // No /S ⇒ prefix-only labels (Table 159 NOTE); a tree that
        // starts at index 2 leaves pages 0–1 on 1-based decimals.
        let ranges = vec![PageLabelRange {
            start_index: 2,
            style: None,
            prefix: "Contents".into(),
            start_value: 1,
        }];
        let labels = labels_for_pages(&ranges, 4);
        assert_eq!(labels, vec!["1", "2", "Contents", "Contents"]);
    }
}
