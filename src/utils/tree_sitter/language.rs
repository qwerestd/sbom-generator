extern "C" {
    fn tree_sitter_xml() -> tree_sitter::Language;
    fn tree_sitter_json() -> tree_sitter::Language;
    fn tree_sitter_yaml() -> tree_sitter::Language;
}

pub fn get_tree_sitter_xml() -> tree_sitter::Language {
    unsafe { tree_sitter_xml() }
}

pub fn get_tree_sitter_json() -> tree_sitter::Language {
    unsafe { tree_sitter_json() }
}

pub fn get_tree_sitter_yaml() -> tree_sitter::Language {
    unsafe { tree_sitter_yaml() }
}
