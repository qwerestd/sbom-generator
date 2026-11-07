/// Separate manifest constraints from explicitly pinned versions. This does not resolve ranges.
pub fn manifest_version(raw: Option<&str>, ecosystem: &str) -> (Option<String>, Option<String>) {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return (None, None);
    };
    let candidate = match ecosystem {
        "maven" | "gradle" => Some(raw),
        "cargo" => raw.strip_prefix('='),
        "pypi" => raw.strip_prefix("==").or_else(|| {
            // Poetry also accepts an unadorned exact version.
            raw.chars().next().filter(char::is_ascii_digit).map(|_| raw)
        }),
        _ => Some(raw.strip_prefix('=').unwrap_or(raw)),
    };
    let exact = candidate.map(str::trim).filter(|s| {
        if matches!(ecosystem, "maven" | "gradle") {
            return !s.chars().any(|c| c.is_whitespace() || "[](),+*$<>=!|".contains(c))
                && !matches!(s.to_ascii_lowercase().as_str(), "latest.release" | "latest.integration" | "latest" | "release" | "runtime");
        }
        if ecosystem == "pypi" {
            // PEP 440 release, pre/post/dev releases, epoch and local labels.
            return regex::Regex::new(r"(?ix)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$")
                .expect("valid PEP 440 regex").is_match(s);
        }
        let numeric = s.strip_prefix('v').unwrap_or(s);
        let core = numeric.split(['-', '+']).next().unwrap_or("");
        let parts: Vec<_> = core.split('.').collect();
        (ecosystem == "pypi" || parts.len() == 3)
            && !parts.is_empty()
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            && !s
                .chars()
                .any(|c| c.is_whitespace() || "*^~<>=!,|[]()$:/".contains(c))
    });
    match exact {
        Some(version) => (Some(version.to_string()), None),
        None => (None, Some(raw.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_are_not_resolved_versions() {
        for (eco, raw) in [
            ("npm", "^1.2.3"),
            ("npm", "1.2"),
            ("npm", "latest"),
            ("npm", "*"),
            ("npm", ">=1.0.0 <2.0.0"),
            ("npm", "1.x"),
            ("cargo", "1.2.3"),
            ("cargo", "~1.2"),
            ("pypi", ">=1.0,<2"),
            ("pypi", "!=1.2"),
            ("pypi", "==1.2.*"),
            ("maven", "[1.0,2.0)"),
            ("gradle", "1.+"),
            ("gradle", "latest.release"),
        ] {
            assert_eq!(
                manifest_version(Some(raw), eco),
                (None, Some(raw.to_owned()))
            );
        }
        for (eco, raw, expected) in [
            ("npm", "1.2.3", "1.2.3"),
            ("cargo", "=1.2.3", "1.2.3"),
            ("pypi", "==1.2.3", "1.2.3"),
            ("pypi", "==2.0rc1", "2.0rc1"),
            ("pypi", "==1!2.0.post1+cpu", "1!2.0.post1+cpu"),
            ("maven", "1.0-SNAPSHOT", "1.0-SNAPSHOT"),
            ("gradle", "1.2", "1.2"),
        ] {
            assert_eq!(
                manifest_version(Some(raw), eco),
                (Some(expected.to_owned()), None)
            );
        }
    }
}
