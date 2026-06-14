//! Resource-dictionary collector — ExtGState, Pattern, XObject.
//!
//! The writer walks the [`oxideav_core::vector::Group`] tree and, every
//! time it needs a non-inlineable resource (a per-group opacity, a
//! gradient, or an embedded raster image), it asks the
//! [`ResourceCollector`] for a name. The collector returns one of
//! `GS<n>` / `Pat<n>` / `Im<n>` and remembers the underlying object so
//! it can later flatten the whole bundle into the page's `/Resources`
//! dictionary.
//!
//! Names are deduplicated by content: two identical [`LinearGradient`]s
//! map to the same `Pat<n>` so the page content stream stays compact.
//!
//! All resources end up as indirect objects (`<n> <gen> obj`) inside
//! the [`crate::objects::Document`] — gradients and images are stream
//! objects, opacity dicts are inline `<<...>>`. The
//! `flatten_into_resources_dict` method emits the page-level
//! `/Resources` dictionary entries (`/ExtGState`, `/Pattern`,
//! `/XObject`) in one pass.

use oxideav_core::vector::{GradientStop, LinearGradient, RadialGradient, SpreadMethod};
use oxideav_core::VideoFrame;

use crate::objects::{Dict, Document, Object, ObjectId, Stream};

// ---- Public collector ---------------------------------------------------

#[derive(Default)]
pub struct ResourceCollector {
    pub(crate) ext_gstates: Vec<ExtGState>,
    pub(crate) gradients: Vec<GradientResource>,
    pub(crate) images: Vec<ImageResource>,
}

impl ResourceCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a per-group opacity (`/ca` + `/CA`) and return the
    /// `GS<n>` name to reference from the content stream via `gs`.
    pub fn add_opacity(&mut self, opacity: f32) -> String {
        // Quantise to 6 decimal digits so two visually-identical
        // opacity calls don't end up with two ExtGState entries.
        let key = (opacity.clamp(0.0, 1.0) * 1_000_000.0).round() as u32;
        if let Some(i) = self
            .ext_gstates
            .iter()
            .position(|g| matches!(g, ExtGState::Opacity(k) if *k == key))
        {
            return format!("GS{i}");
        }
        let i = self.ext_gstates.len();
        self.ext_gstates.push(ExtGState::Opacity(key));
        format!("GS{i}")
    }

    pub fn add_linear_gradient(&mut self, g: &LinearGradient) -> String {
        let snapshot = LinearGradientKey {
            start: (g.start.x.to_bits(), g.start.y.to_bits()),
            end: (g.end.x.to_bits(), g.end.y.to_bits()),
            stops: stops_key(&g.stops),
            spread: g.spread,
        };
        if let Some(i) = self.gradients.iter().position(|r| match r {
            GradientResource::Linear(_, k) => k == &snapshot,
            _ => false,
        }) {
            return format!("Pat{i}");
        }
        let i = self.gradients.len();
        self.gradients
            .push(GradientResource::Linear(g.clone(), snapshot));
        format!("Pat{i}")
    }

    pub fn add_radial_gradient(&mut self, g: &RadialGradient) -> String {
        let snapshot = RadialGradientKey {
            center: (g.center.x.to_bits(), g.center.y.to_bits()),
            radius: g.radius.to_bits(),
            focal: g.focal.map(|p| (p.x.to_bits(), p.y.to_bits())),
            stops: stops_key(&g.stops),
            spread: g.spread,
        };
        if let Some(i) = self.gradients.iter().position(|r| match r {
            GradientResource::Radial(_, k) => k == &snapshot,
            _ => false,
        }) {
            return format!("Pat{i}");
        }
        let i = self.gradients.len();
        self.gradients
            .push(GradientResource::Radial(g.clone(), snapshot));
        format!("Pat{i}")
    }

    /// Register one [`VideoFrame`] as an `Image` XObject and return
    /// the `Im<n>` name. Round 1 supports a single straight-RGBA8
    /// plane (the layout produced by every vector-→-raster
    /// rasteriser in the workspace); other layouts return `None` and
    /// the caller skips the image.
    ///
    /// `width` / `height` come from the [`ImageRef::bounds`]
    /// rectangle — `VideoFrame` itself doesn't carry geometry.
    pub fn add_rgba_image(
        &mut self,
        frame: &VideoFrame,
        width: u32,
        height: u32,
    ) -> Option<String> {
        if width == 0 || height == 0 {
            return None;
        }
        let plane = frame.planes.first()?;
        if plane.data.is_empty() {
            return None;
        }
        // Round-1 acceptance test: the single plane carries exactly
        // 4 bytes per pixel. The stride must be at least that, but
        // 0 (the conventional "tightly packed" sentinel) is also OK
        // — the image builder substitutes `width * 4` in that case.
        let row_bytes = (width as usize) * 4;
        if plane.stride != 0 && plane.stride < row_bytes {
            return None;
        }
        if plane.data.len() < row_bytes * (height as usize)
            && plane.stride != 0
            && plane.data.len() < plane.stride * (height as usize)
        {
            return None;
        }
        let i = self.images.len();
        self.images.push(ImageResource {
            width,
            height,
            stride: plane.stride,
            data: plane.data.clone(),
            kind: ImageKind::Rgba8,
        });
        Some(format!("Im{i}"))
    }

    /// Build the `/Resources` dictionary that the Page object
    /// references (object id 4 in the layout the writer uses) and add
    /// every dependent indirect object (Pattern shading dicts, Image
    /// XObjects, ExtGState dicts) to `doc`.
    pub fn flatten_into_resources_dict(&self, doc: &mut Document) -> Object {
        let mut res = Dict::new();

        if !self.ext_gstates.is_empty() {
            let mut ext = Dict::new();
            for (i, g) in self.ext_gstates.iter().enumerate() {
                let dict = match g {
                    ExtGState::Opacity(key) => {
                        let alpha = (*key as f64) / 1_000_000.0;
                        Dict::new()
                            .with("Type", Object::Name("ExtGState".into()))
                            .with("ca", Object::Real(alpha))
                            .with("CA", Object::Real(alpha))
                    }
                };
                ext.set(&format!("GS{i}"), Object::Dict(dict));
            }
            res.set("ExtGState", Object::Dict(ext));
        }

        if !self.gradients.is_empty() {
            let mut pats = Dict::new();
            for (i, g) in self.gradients.iter().enumerate() {
                let pattern_id = build_gradient_pattern(doc, g);
                pats.set(&format!("Pat{i}"), Object::Reference(pattern_id));
            }
            res.set("Pattern", Object::Dict(pats));
        }

        if !self.images.is_empty() {
            let mut xobj = Dict::new();
            for (i, img) in self.images.iter().enumerate() {
                let id = build_image_xobject(doc, img);
                xobj.set(&format!("Im{i}"), Object::Reference(id));
            }
            res.set("XObject", Object::Dict(xobj));
        }

        // Always declare DeviceRGB / Pattern as supported colour
        // spaces so PDF readers don't have to infer from per-paint
        // operators. /CS is a Page-level optional entry but it makes
        // the file more obviously valid to qpdf --check.
        res.set(
            "ProcSet",
            Object::Array(vec![
                Object::Name("PDF".into()),
                Object::Name("ImageC".into()),
            ]),
        );

        Object::Dict(res)
    }

    /// True iff no resources were collected — the page can elect to
    /// emit an empty `/Resources << >>` or omit the entry entirely.
    pub fn is_empty(&self) -> bool {
        self.ext_gstates.is_empty() && self.gradients.is_empty() && self.images.is_empty()
    }
}

// ---- Internal record types ---------------------------------------------

#[derive(Clone)]
pub(crate) enum ExtGState {
    Opacity(u32),
}

#[derive(Clone)]
pub(crate) enum GradientResource {
    Linear(LinearGradient, LinearGradientKey),
    Radial(RadialGradient, RadialGradientKey),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinearGradientKey {
    start: (u32, u32),
    end: (u32, u32),
    stops: Vec<(u32, [u8; 4])>,
    spread: SpreadMethod,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RadialGradientKey {
    center: (u32, u32),
    radius: u32,
    focal: Option<(u32, u32)>,
    stops: Vec<(u32, [u8; 4])>,
    spread: SpreadMethod,
}

#[derive(Clone)]
pub(crate) struct ImageResource {
    width: u32,
    height: u32,
    stride: usize,
    data: Vec<u8>,
    /// Reserved for round-2 — DCTDecode (JPEG passthrough), CCITTFax
    /// (single-bit), etc. Round 1 is always `Rgba8`.
    #[allow(dead_code)]
    kind: ImageKind,
}

#[derive(Clone, Copy)]
pub(crate) enum ImageKind {
    Rgba8,
}

fn stops_key(stops: &[GradientStop]) -> Vec<(u32, [u8; 4])> {
    stops
        .iter()
        .map(|s| {
            (
                s.offset.to_bits(),
                [s.color.r, s.color.g, s.color.b, s.color.a],
            )
        })
        .collect()
}

// ---- Gradient → PDF pattern --------------------------------------------

fn build_gradient_pattern(doc: &mut Document, g: &GradientResource) -> ObjectId {
    let (shading, function_dict) = match g {
        GradientResource::Linear(lin, _) => {
            let func = build_gradient_function(doc, &lin.stops);
            let mut sh = Dict::new()
                .with("ShadingType", Object::Integer(2)) // axial
                .with("ColorSpace", Object::Name("DeviceRGB".into()))
                .with(
                    "Coords",
                    Object::Array(vec![
                        Object::Real(lin.start.x as f64),
                        Object::Real(lin.start.y as f64),
                        Object::Real(lin.end.x as f64),
                        Object::Real(lin.end.y as f64),
                    ]),
                )
                .with("Function", Object::Reference(func));
            apply_extend(&mut sh, lin.spread);
            (sh, func)
        }
        GradientResource::Radial(rad, _) => {
            let func = build_gradient_function(doc, &rad.stops);
            let focal = rad.focal.unwrap_or(rad.center);
            // PDF radial gradients (`ShadingType 3`) are described by
            // two circles and interpolate from c0(focal,r0=0) to
            // c1(center,radius). Round 1 fixes the focal radius at 0
            // — same as SVG's `fx`/`fy` semantics.
            let mut sh = Dict::new()
                .with("ShadingType", Object::Integer(3))
                .with("ColorSpace", Object::Name("DeviceRGB".into()))
                .with(
                    "Coords",
                    Object::Array(vec![
                        Object::Real(focal.x as f64),
                        Object::Real(focal.y as f64),
                        Object::Real(0.0),
                        Object::Real(rad.center.x as f64),
                        Object::Real(rad.center.y as f64),
                        Object::Real(rad.radius as f64),
                    ]),
                )
                .with("Function", Object::Reference(func));
            apply_extend(&mut sh, rad.spread);
            (sh, func)
        }
    };
    // The Pattern object itself: PatternType 2 = Shading pattern.
    let pattern = Object::Dict(
        Dict::new()
            .with("Type", Object::Name("Pattern".into()))
            .with("PatternType", Object::Integer(2))
            .with("Shading", Object::Dict(shading)),
    );
    let _ = function_dict; // already added to doc
    doc.add(pattern)
}

fn apply_extend(sh: &mut Dict, spread: SpreadMethod) {
    // Extend [false false] = colour outside the start/end is
    // background; [true true] = pad. Reflect / Repeat are not
    // expressible in a single PDF axial shader; we approximate with
    // /Extend [true true] (pad) — round-2 should multi-shading them.
    let extend = match spread {
        SpreadMethod::Pad => Object::Array(vec![Object::Bool(true), Object::Bool(true)]),
        SpreadMethod::Reflect | SpreadMethod::Repeat => {
            Object::Array(vec![Object::Bool(true), Object::Bool(true)])
        }
    };
    sh.set("Extend", extend);
}

fn build_gradient_function(doc: &mut Document, stops: &[GradientStop]) -> ObjectId {
    // Sort stops by offset and clamp to [0,1].
    let mut s: Vec<GradientStop> = stops.to_vec();
    s.sort_by(|a, b| {
        a.offset
            .partial_cmp(&b.offset)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if s.is_empty() {
        // Degenerate — single black-to-black "function".
        let dict = Dict::new()
            .with("FunctionType", Object::Integer(2))
            .with(
                "Domain",
                Object::Array(vec![Object::Real(0.0), Object::Real(1.0)]),
            )
            .with(
                "C0",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(0.0),
                ]),
            )
            .with(
                "C1",
                Object::Array(vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(0.0),
                ]),
            )
            .with("N", Object::Real(1.0));
        return doc.add(Object::Dict(dict));
    }

    if s.len() == 1 {
        // Single stop — emit a degenerate Type 2 with C0 == C1.
        let c = s[0].color;
        let arr = vec![
            Object::Real(c.r as f64 / 255.0),
            Object::Real(c.g as f64 / 255.0),
            Object::Real(c.b as f64 / 255.0),
        ];
        let dict = Dict::new()
            .with("FunctionType", Object::Integer(2))
            .with(
                "Domain",
                Object::Array(vec![Object::Real(0.0), Object::Real(1.0)]),
            )
            .with("C0", Object::Array(arr.clone()))
            .with("C1", Object::Array(arr))
            .with("N", Object::Real(1.0));
        return doc.add(Object::Dict(dict));
    }

    // Multiple stops — wrap n-1 Type-2 segments inside one Type-3
    // stitching function. Domain spans the first stop's offset to the
    // last; Bounds lists the interior stop offsets; Functions is the
    // segment list; Encode maps each segment back to [0,1].
    let mut function_ids = Vec::with_capacity(s.len() - 1);
    let mut bounds = Vec::with_capacity(s.len() - 2);
    let mut encode = Vec::with_capacity((s.len() - 1) * 2);
    for i in 0..(s.len() - 1) {
        let c0 = s[i].color;
        let c1 = s[i + 1].color;
        let seg = Dict::new()
            .with("FunctionType", Object::Integer(2))
            .with(
                "Domain",
                Object::Array(vec![Object::Real(0.0), Object::Real(1.0)]),
            )
            .with(
                "C0",
                Object::Array(vec![
                    Object::Real(c0.r as f64 / 255.0),
                    Object::Real(c0.g as f64 / 255.0),
                    Object::Real(c0.b as f64 / 255.0),
                ]),
            )
            .with(
                "C1",
                Object::Array(vec![
                    Object::Real(c1.r as f64 / 255.0),
                    Object::Real(c1.g as f64 / 255.0),
                    Object::Real(c1.b as f64 / 255.0),
                ]),
            )
            .with("N", Object::Real(1.0));
        let id = doc.add(Object::Dict(seg));
        function_ids.push(Object::Reference(id));
        if i > 0 {
            bounds.push(Object::Real(s[i].offset as f64));
        }
        encode.push(Object::Real(0.0));
        encode.push(Object::Real(1.0));
    }

    let domain_lo = s.first().unwrap().offset as f64;
    let domain_hi = s.last().unwrap().offset as f64;
    let stitch = Dict::new()
        .with("FunctionType", Object::Integer(3))
        .with(
            "Domain",
            Object::Array(vec![Object::Real(domain_lo), Object::Real(domain_hi)]),
        )
        .with("Functions", Object::Array(function_ids))
        .with("Bounds", Object::Array(bounds))
        .with("Encode", Object::Array(encode));
    doc.add(Object::Dict(stitch))
}

// ---- Image → XObject ---------------------------------------------------

fn build_image_xobject(doc: &mut Document, img: &ImageResource) -> ObjectId {
    // RGBA8: split colour and alpha planes — PDF Image XObjects with
    // an `/SMask` give per-pixel alpha (the colour stream stays pure
    // RGB).
    let stride = if img.stride == 0 {
        (img.width as usize) * 4
    } else {
        img.stride
    };
    let n = (img.width as usize) * (img.height as usize);
    let mut rgb = Vec::with_capacity(n * 3);
    let mut alpha = Vec::with_capacity(n);
    for y in 0..(img.height as usize) {
        let row_off = y * stride;
        for x in 0..(img.width as usize) {
            let p = row_off + x * 4;
            if p + 3 >= img.data.len() {
                // Bounds-check guard for malformed inputs — emit a
                // sane black pixel rather than panicking.
                rgb.extend_from_slice(&[0, 0, 0]);
                alpha.push(255);
            } else {
                rgb.push(img.data[p]);
                rgb.push(img.data[p + 1]);
                rgb.push(img.data[p + 2]);
                alpha.push(img.data[p + 3]);
            }
        }
    }

    let rgb_compressed = flate_compress(&rgb);
    let alpha_compressed = flate_compress(&alpha);

    let smask_dict = Dict::new()
        .with("Type", Object::Name("XObject".into()))
        .with("Subtype", Object::Name("Image".into()))
        .with("Width", Object::Integer(img.width as i64))
        .with("Height", Object::Integer(img.height as i64))
        .with("ColorSpace", Object::Name("DeviceGray".into()))
        .with("BitsPerComponent", Object::Integer(8))
        .with("Filter", Object::Name("FlateDecode".into()));
    let smask_id = doc.add(Object::Stream(Stream::new(smask_dict, alpha_compressed)));

    let dict = Dict::new()
        .with("Type", Object::Name("XObject".into()))
        .with("Subtype", Object::Name("Image".into()))
        .with("Width", Object::Integer(img.width as i64))
        .with("Height", Object::Integer(img.height as i64))
        .with("ColorSpace", Object::Name("DeviceRGB".into()))
        .with("BitsPerComponent", Object::Integer(8))
        .with("Filter", Object::Name("FlateDecode".into()))
        .with("SMask", Object::Reference(smask_id));
    doc.add(Object::Stream(Stream::new(dict, rgb_compressed)))
}

fn flate_compress(input: &[u8]) -> Vec<u8> {
    crate::zlib::flate_compress(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::vector::{LinearGradient, Point, Rgba, SpreadMethod};

    #[test]
    fn opacity_dedup_returns_same_name() {
        let mut r = ResourceCollector::new();
        let n1 = r.add_opacity(0.5);
        let n2 = r.add_opacity(0.5);
        assert_eq!(n1, n2);
        assert_eq!(r.ext_gstates.len(), 1);
    }

    #[test]
    fn linear_gradient_dedup() {
        let g = LinearGradient {
            start: Point::new(0.0, 0.0),
            end: Point::new(100.0, 0.0),
            stops: vec![
                GradientStop::new(0.0, Rgba::opaque(255, 0, 0)),
                GradientStop::new(1.0, Rgba::opaque(0, 0, 255)),
            ],
            spread: SpreadMethod::Pad,
        };
        let mut r = ResourceCollector::new();
        let a = r.add_linear_gradient(&g);
        let b = r.add_linear_gradient(&g);
        assert_eq!(a, b);
        assert_eq!(r.gradients.len(), 1);
    }

    #[test]
    fn opacity_ext_gstate_emits_ca_and_cap_ca() {
        let mut r = ResourceCollector::new();
        r.add_opacity(0.5);
        let mut doc = Document::new();
        let res = r.flatten_into_resources_dict(&mut doc);
        // Stitch the resources into a minimal Catalog so write_to
        // accepts the document — the test only cares about the
        // serialised bytes containing the right ExtGState markers.
        let res_id = doc.add(res);
        let catalog_id = doc.add(Object::Dict(
            Dict::new()
                .with("Type", Object::Name("Catalog".into()))
                .with("Pages", Object::Reference(res_id)),
        ));
        doc.root = Some(catalog_id);
        let mut buf = Vec::new();
        doc.write_to(&mut buf).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("/ExtGState"));
        assert!(s.contains("/ca 0.5"));
        assert!(s.contains("/CA 0.5"));
    }
}
