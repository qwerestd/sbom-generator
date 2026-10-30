use std::path::Path;

use crate::model::dependency::DependencyLocation;
use crate::model::location::Location;
use crate::model::position::{get_position_in_string, Position};

pub fn get_tree(
    code: &str,
    tree_sitter_language: &tree_sitter::Language,
) -> Option<tree_sitter::Tree> {
    let mut tree_sitter_parser = tree_sitter::Parser::new();
    tree_sitter_parser.set_language(tree_sitter_language).ok()?;
    tree_sitter_parser.parse(code, None)
}

/// 将 Maven 模块基于字节偏移量提取精确行列号 (`Line`/`Col`) 的能力推广到全工程任意文本/AST节点
pub fn build_location_from_offsets(
    path: &Path,
    content: &str,
    block_range: (usize, usize),
    name_range: Option<(usize, usize)>,
    version_range: Option<(usize, usize)>,
) -> DependencyLocation {
    let file_str = path.display().to_string();

    let to_loc = |(start_b, end_b): (usize, usize)| -> Location {
        let safe_end = end_b.saturating_sub(1).max(start_b);
        let start = get_position_in_string(content, start_b).unwrap_or_default();
        let end = get_position_in_string(content, safe_end).unwrap_or(Position {
            line: start.line,
            col: start.col,
        });
        Location {
            file: file_str.clone(),
            start,
            end,
        }
    };

    let block_loc = to_loc(block_range);
    let name_loc = name_range.map(to_loc).unwrap_or_else(|| block_loc.clone());
    let ver_loc = version_range.map(to_loc);

    DependencyLocation {
        block: block_loc,
        name: name_loc,
        version: ver_loc,
    }
}
