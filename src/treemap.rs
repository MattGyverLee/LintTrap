//! Squarified treemap layout over a scan tree.

use crate::scan::{Kind, Tree};
use eframe::egui::{pos2, vec2, Rect};

#[derive(Clone, Copy, Debug)]
pub struct Cell {
    pub node: u32,
    pub rect: Rect,
    pub depth: u8,
    /// Index of the enclosing cell in the output, if any.
    pub parent: Option<usize>,
}

/// Height reserved for a folder's label strip when its children are drawn inside it.
pub const HEADER: f32 = 17.0;

/// Squarified layout (Bruls, Huizing, van Wijk). `items` must be sorted largest first.
fn squarify(items: &[(u32, f64)], mut r: Rect, out: &mut Vec<(u32, Rect)>) {
    let total: f64 = items.iter().map(|i| i.1).sum();
    if total <= 0.0 || r.width() < 1.0 || r.height() < 1.0 {
        return;
    }
    let scale = (r.width() as f64 * r.height() as f64) / total;
    let mut i = 0;
    while i < items.len() {
        let wide = r.width() >= r.height();
        let short = if wide { r.height() } else { r.width() } as f64;
        if short <= 0.0 {
            break;
        }
        let (mut j, mut sum, mut best, mut mx, mut mn) = (i, 0.0f64, f64::INFINITY, 0.0f64, f64::INFINITY);
        while j < items.len() {
            let a = items[j].1 * scale;
            let s = sum + a;
            let (nmx, nmn) = (mx.max(a), mn.min(a));
            let worst = ((short * short * nmx) / (s * s)).max((s * s) / (short * short * nmn));
            if worst > best && j > i {
                break;
            }
            best = worst;
            sum = s;
            mx = nmx;
            mn = nmn;
            j += 1;
        }
        let thick = (sum / short) as f32;
        let mut off = 0.0f32;
        for item in &items[i..j] {
            let len = (item.1 * scale / sum * short) as f32;
            let rect = if wide {
                Rect::from_min_size(pos2(r.min.x, r.min.y + off), vec2(thick, len))
            } else {
                Rect::from_min_size(pos2(r.min.x + off, r.min.y), vec2(len, thick))
            };
            out.push((item.0, rect));
            off += len;
        }
        if wide {
            r.min.x += thick;
        } else {
            r.min.y += thick;
        }
        i = j;
    }
}

/// Lay out `node`'s children inside `rect`, nesting folders up to `max_depth` levels.
pub fn layout(tree: &Tree, node: u32, rect: Rect, max_depth: u8) -> Vec<Cell> {
    let mut out = Vec::new();
    layout_into(tree, node, rect, 1, max_depth, None, &mut out);
    out
}

fn layout_into(tree: &Tree, node: u32, rect: Rect, depth: u8, max_depth: u8, parent: Option<usize>, out: &mut Vec<Cell>) {
    let n = &tree.nodes[node as usize];
    let items: Vec<(u32, f64)> = n
        .children
        .iter()
        .map(|&c| (c, tree.nodes[c as usize].size as f64))
        .filter(|(_, s)| *s > 0.0)
        .collect();
    let mut placed = Vec::with_capacity(items.len());
    squarify(&items, rect, &mut placed);
    for (child, r) in placed {
        if r.width() < 1.5 || r.height() < 1.5 {
            continue;
        }
        let idx = out.len();
        out.push(Cell { node: child, rect: r, depth, parent });
        let cn = &tree.nodes[child as usize];
        if depth < max_depth && cn.kind == Kind::Dir && !cn.children.is_empty() && r.width() > 56.0 && r.height() > 44.0 {
            let inner = Rect::from_min_max(pos2(r.min.x + 3.0, r.min.y + HEADER), pos2(r.max.x - 3.0, r.max.y - 3.0));
            layout_into(tree, child, inner, depth + 1, max_depth, Some(idx), out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squarify_fills_the_rect_without_overlap() {
        let items: Vec<(u32, f64)> = vec![(0, 60.0), (1, 30.0), (2, 6.0), (3, 3.0), (4, 1.0)];
        let r = Rect::from_min_size(pos2(0.0, 0.0), vec2(400.0, 300.0));
        let mut out = Vec::new();
        squarify(&items, r, &mut out);
        assert_eq!(out.len(), 5);
        let area: f32 = out.iter().map(|(_, r)| r.area()).sum();
        assert!((area - 120_000.0).abs() < 1.0, "area {area}");
        for (i, (_, a)) in out.iter().enumerate() {
            assert!(r.expand(0.01).contains_rect(*a));
            for (_, b) in out.iter().skip(i + 1) {
                assert!(a.intersect(*b).area() < 0.5, "overlap {a:?} {b:?}");
            }
        }
        // Proportional: first item gets 60% of the area.
        assert!((out[0].1.area() / 120_000.0 - 0.6).abs() < 0.01);
    }
}
