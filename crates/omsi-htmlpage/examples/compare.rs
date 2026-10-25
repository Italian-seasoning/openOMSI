//! What a page costs the game on each engine: `compare <classic|modern> <pages> <frames> <page.html>`.
//!
//! Makes `pages` renderers of the file (the same page on several displays), feeds each every frame
//! like the game does (changed variables in, a picture out) and prints the time the game thread
//! spends per frame. Run it under `/usr/bin/time -l` for the memory and the CPU of the whole process
//! (the modern engine's page threads included).

use omsi_sim::htmltex::{HtmlRenderer, PageApi};
use std::time::Instant;

fn make(engine: &str, html: &str) -> Box<dyn HtmlRenderer> {
    match engine {
        "classic" => Box::new(omsi_htmlengine::EngineRenderer::with_api(800, 480, html, PageApi::Vehicle)),
        "modern" => Box::new(omsi_htmlpage::EngineRenderer::with_api(800, 480, html, PageApi::Vehicle)),
        other => panic!("engine is classic or modern, not {other}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (engine, pages, frames, file) = (&args[1], args[2].parse::<usize>().unwrap(), args[3].parse::<usize>().unwrap(), &args[4]);
    let html = std::fs::read_to_string(file).unwrap();
    let dir = std::path::Path::new(file).parent().unwrap().to_path_buf();
    let t = Instant::now();
    let mut rs: Vec<Box<dyn HtmlRenderer>> = (0..pages).map(|_| make(engine, &html)).collect();
    for r in &mut rs {
        r.set_asset_dirs(vec![dir.clone()]);
        let _ = r.poll_frame();
    }
    let created = t.elapsed().as_secs_f64() * 1000.0;
    let mut per_frame = Vec::with_capacity(frames);
    let mut drawn = 0usize;
    for f in 0..frames {
        let t = Instant::now();
        for (i, r) in rs.iter_mut().enumerate() {
            let speed = ((f + i * 7) % 90) as f32;
            r.set_vars(&[("Velocity".to_string(), speed), ("Engine_N".to_string(), 700.0 + speed * 20.0), ("clock".to_string(), (f / 60) as f32)], &[("destination".to_string(), format!("Stop {}", f / 120))]);
            if r.poll_frame().is_some() {
                drawn += 1;
            }
            let _ = r.take_events();
        }
        per_frame.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    per_frame.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = per_frame.iter().sum::<f64>() / per_frame.len() as f64;
    let p = |q: f64| per_frame[((per_frame.len() - 1) as f64 * q) as usize];
    println!("{engine} pages={pages} frames={frames} created={created:.1}ms drawn={drawn} per-frame(ms): mean={mean:.3} p50={:.3} p95={:.3} p99={:.3} max={:.3}", p(0.5), p(0.95), p(0.99), per_frame[per_frame.len() - 1]);
}
