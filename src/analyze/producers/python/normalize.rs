use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref PEP503_NORM_RE: Regex = Regex::new(r"[-_.]+").unwrap();
}

pub fn canonicalize_name(raw: &str) -> String {
    PEP503_NORM_RE
        .replace_all(&raw.to_lowercase(), "-")
        .to_string()
}
