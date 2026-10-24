//! The built-in backend of `[htmltexture]`: an HTML/CSS/JavaScript engine that needs no
//! browser, so it runs the same on every desktop and on Android. What a page may use is
//! written in `docs/HTMLTEXTURE.md`.
//!
//! # Layout of this crate
//! * `dom`: the HTML parser, the selectors and the CSS parser. `style`: computed style and
//!   values. `layout`: block flow, inline text, flexbox, positions. `canvas`: pixels and the
//!   painter.
//! * `page`: a page running - its state, the host primitives (`__host`) and the script context.
//!   The scripts run in Boa; `prelude.js` makes the browser objects (`document`, events, timers,
//!   `window.omsi`) out of those primitives.
//! * `renderer`: [`EngineRenderer`], the [`HtmlRenderer`] backend. Boa's context is not `Send`, so a
//!   page lives on a thread of its own and each call is a round trip to it.
//!
//! The page talks to the vehicle through `window.omsi`:
//! * the host calls `window.omsi.update({ num: {name: value}, str: {name: "text"}, vars, vehicle })`
//!   with the script variables that changed (all of them on the first call);
//! * the page calls `window.omsi.setVar(name, value)` to write a script variable back and
//!   `window.omsi.trigger(name)` to press a trigger of the vehicle's scripts;
//! * `window.omsi.vehicle`, `.vars.num`/`.str`, `.getVar(name)`, `.time`, `.date`, `.locale`,
//!   `.depot`, `.departures`/`.getDepartures(stop)` and the IBIS requests `.setRoute`, `.setLine`,
//!   `.setDestination`, `.setNextStop`, `.clearLine` are described in `docs/HTMLTEXTURE.md` and
//!   [`omsi_sim::vehicle_api`].
//! * a press on the texture ([`HtmlRenderer::pointer`]) becomes `pointerdown`, `mousedown`,
//!   `pointerup`, `mouseup` and `click` events on the element under it, bubbling up.

use omsi_sim::htmltex::{HtmlRenderer, PointerKind};
use ab_glyph::{point, Font, FontRef, PxScale, ScaleFont, VariableFont};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod canvas;
mod dom;
mod images;
mod layout;
mod page;
mod renderer;
mod style;

use canvas::*;
use dom::*;
use images::*;
use layout::*;
use style::*;

pub use renderer::EngineRenderer;

pub(crate) const INTER: &[u8] = include_bytes!("../../../assets/fonts/InterVariable.ttf");
thread_local! {
    /// The regular and the bold face, parsed once per thread instead of once per frame.
    static FONTS: Option<(FontRef<'static>, FontRef<'static>)> = FontRef::try_from_slice(INTER).ok().map(|reg| {
        let mut bold = reg.clone();
        bold.set_variation(b"wght", 700.0);
        (reg, bold)
    });
}

/// Run `f` with the regular and the bold face; `None` when the font does not parse.
pub(crate) fn with_fonts<R>(f: impl FnOnce(&FontRef<'static>, &FontRef<'static>) -> R) -> Option<R> {
    FONTS.with(|p| p.as_ref().map(|(reg, bold)| f(reg, bold)))
}

/// The bytes of the face for the characters Inter lacks (Hangul, CJK ...): the file in
/// `OMSI_HTML_FALLBACK_FONT` (and `..._BOLD`), else Malgun Gothic from the Windows fonts or
/// AppleGothic on macOS.
/// Read once per process; `None` when there is none.
fn fallback_bytes() -> Option<&'static (Vec<u8>, Vec<u8>)> {
    static BYTES: std::sync::OnceLock<Option<(Vec<u8>, Vec<u8>)>> = std::sync::OnceLock::new();
    BYTES
        .get_or_init(|| {
            let read = |p: &std::path::Path| std::fs::read(p).ok();
            if let Some(reg) = omsi_cfg::flags::OMSI_HTML_FALLBACK_FONT.os().and_then(|p| read(p.as_ref())) {
                let bold = omsi_cfg::flags::OMSI_HTML_FALLBACK_FONT_BOLD
                    .os()
                    .and_then(|p| read(p.as_ref()))
                    .unwrap_or_else(|| reg.clone());
                return Some((reg, bold));
            }
            if cfg!(target_os = "macos") {
                let reg = read(std::path::Path::new("/System/Library/Fonts/Supplemental/AppleGothic.ttf"))?;
                return Some((reg.clone(), reg));
            }
            let dir = std::path::PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into())).join("Fonts");
            let reg = read(&dir.join("malgun.ttf"))?;
            let bold = read(&dir.join("malgunbd.ttf")).unwrap_or_else(|| reg.clone());
            Some((reg, bold))
        })
        .as_ref()
}

thread_local! {
    static FALLBACK: Option<(FontRef<'static>, FontRef<'static>)> = fallback_bytes().and_then(|(reg, bold)| {
        Some((FontRef::try_from_slice(reg).ok()?, FontRef::try_from_slice(bold).ok()?))
    });
}

/// The face that draws `ch`, its glyph and which face it is (0 = `font`, 1 = the fallback):
/// `font` itself, or the fallback face when `font` has no glyph for it.
pub(crate) fn face_for<R>(font: &FontRef<'static>, bold: bool, ch: char, f: impl FnOnce(&FontRef<'static>, ab_glyph::GlyphId, u8) -> R) -> R {
    let id = font.glyph_id(ch);
    if id.0 != 0 || ch.is_ascii() {
        return f(font, id, 0);
    }
    FALLBACK.with(|fb| match fb {
        Some((reg, b)) => {
            let face = if bold { b } else { reg };
            let fid = face.glyph_id(ch);
            if fid.0 != 0 { f(face, fid, 1) } else { f(font, id, 0) }
        }
        None => f(font, id, 0),
    })
}

pub(crate) const STEP_LIMIT: u32 = 400_000;
pub(crate) const DEPTH_LIMIT: u32 = 48;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_css;
#[cfg(test)]
mod tests_js;