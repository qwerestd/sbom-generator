use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::Context;
use pep508_rs::{pep440_rs::Version, Requirement, VersionOrUrl};

#[derive(Default)]
pub(crate) struct ProjectRequirements {
    pub roots: Vec<Requirement>,
    pub constraints: Vec<Requirement>,
}

pub(crate) fn parse_requirement(text: &str) -> anyhow::Result<Requirement> {
    Requirement::from_str(text).with_context(|| format!("invalid Python requirement: {text}"))
}

pub(crate) fn version_matches(requirement: &Requirement, version: &str) -> anyhow::Result<bool> {
    let version = Version::from_str(version)?;
    Ok(match &requirement.version_or_url {
        Some(VersionOrUrl::VersionSpecifier(spec)) => spec.contains(&version),
        _ => true,
    })
}

// Poetry's shorthand is not PEP 440. Translate it before passing to the standard parser.
pub(crate) fn poetry_spec(raw: &str) -> anyhow::Result<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "*" {
        return Ok(String::new());
    }
    if raw.contains("||") {
        anyhow::bail!("Poetry union constraint needs static fallback: {raw}");
    }
    let mut clauses = Vec::new();
    for part in raw.split(',').map(str::trim) {
        if let Some(version) = part
            .strip_prefix('^')
            .or_else(|| part.strip_prefix('~').filter(|_| !part.starts_with("~=")))
        {
            let parsed = Version::from_str(version)?;
            let mut upper = parsed.release().to_vec();
            let index = if part.starts_with('^') {
                upper
                    .iter()
                    .position(|n| *n != 0)
                    .unwrap_or(upper.len() - 1)
            } else if upper.len() > 1 {
                1
            } else {
                0
            };
            upper[index] = upper[index]
                .checked_add(1)
                .context("Poetry version bound overflow")?;
            upper.truncate(index + 1);
            clauses.push(format!(
                ">={version},<{}",
                upper
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(".")
            ));
        } else if part.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            clauses.push(format!("=={part}"));
        } else {
            clauses.push(part.to_string());
        }
    }
    Ok(clauses.join(","))
}

impl ProjectRequirements {
    pub fn load(directory: &Path) -> anyhow::Result<Self> {
        let mut result = Self::default();
        let req = directory.join("requirements.txt");
        if req.exists() {
            result.read_requirements(&req, false, &mut HashSet::new())?;
        }
        let project = directory.join("pyproject.toml");
        if project.exists() {
            let content: toml::Value = toml::from_str(&fs::read_to_string(project)?)?;
            if let Some(items) = content
                .get("project")
                .and_then(|p| p.get("dependencies"))
                .and_then(|x| x.as_array())
            {
                for item in items {
                    result.roots.push(parse_requirement(
                        item.as_str()
                            .context("project.dependencies must contain strings")?,
                    )?);
                }
            } else if let Some(table) = content
                .get("tool")
                .and_then(|x| x.get("poetry"))
                .and_then(|x| x.get("dependencies"))
                .and_then(|x| x.as_table())
            {
                result.read_table(table)?;
            }
        }
        let pipfile = directory.join("Pipfile");
        if pipfile.exists() {
            let content: toml::Value = toml::from_str(&fs::read_to_string(pipfile)?)?;
            if let Some(table) = content.get("packages").and_then(|x| x.as_table()) {
                result.read_table(table)?;
            }
        }
        Ok(result)
    }

    fn read_table(&mut self, table: &toml::Table) -> anyhow::Result<()> {
        for (name, value) in table {
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            let variants = value
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(std::slice::from_ref(value));
            for value in variants {
                // Installed version alone cannot establish a local/VCS source's identity.
                anyhow::ensure!(
                    !["path", "git", "url"]
                        .iter()
                        .any(|key| value.get(key).is_some()),
                    "source dependency {name} needs static fallback"
                );
                let version = value
                    .as_str()
                    .or_else(|| value.get("version").and_then(|x| x.as_str()))
                    .unwrap_or("*");
                let extras = value
                    .get("extras")
                    .and_then(|x| x.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .filter(|x| !x.is_empty())
                    .map(|x| format!("[{x}]"))
                    .unwrap_or_default();
                let mut text = format!("{name}{extras}{}", poetry_spec(version)?);
                let mut markers = Vec::new();
                if let Some(marker) = value.get("markers").and_then(|x| x.as_str()) {
                    markers.push(format!("({marker})"));
                }
                if let Some(python) = value.get("python").and_then(|x| x.as_str()) {
                    for clause in poetry_spec(python)?.split(',') {
                        let split = clause
                            .find(|c: char| c.is_ascii_digit())
                            .context("invalid Python constraint")?;
                        markers.push(format!(
                            "python_full_version {} '{}'",
                            &clause[..split],
                            &clause[split..]
                        ));
                    }
                }
                if let Some(platform) = value.get("platform").and_then(|x| x.as_str()) {
                    markers.push(format!("sys_platform == '{platform}'"));
                }
                if !markers.is_empty() {
                    text.push_str(&format!(" ; {}", markers.join(" and ")));
                }
                self.roots.push(parse_requirement(&text)?);
            }
        }
        Ok(())
    }

    fn read_requirements(
        &mut self,
        path: &Path,
        constraint: bool,
        visited: &mut HashSet<(std::path::PathBuf, bool)>,
    ) -> anyhow::Result<()> {
        let canonical =
            fs::canonicalize(path).with_context(|| format!("cannot read {}", path.display()))?;
        if !visited.insert((canonical, constraint)) {
            return Ok(());
        }
        let content = fs::read_to_string(path)?;
        let properties: HashMap<_, _> = std::env::vars().collect();
        // Join logical lines before removing hashes or comments.
        let content = content.replace("\\\r\n", " ").replace("\\\n", " ");
        for raw in content.trim_start_matches('\u{FEFF}').lines() {
            let line = raw
                .split(" #")
                .next()
                .unwrap_or("")
                .split("--hash")
                .next()
                .unwrap_or("")
                .trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let include = [
                ("--requirement", false),
                ("--constraint", true),
                ("-r", false),
                ("-c", true),
            ]
            .iter()
            .find_map(|(flag, mode)| {
                line.strip_prefix(flag)
                    .map(|rest| (rest.trim_start_matches('=').trim(), *mode))
            });
            if let Some((file, mode)) = include {
                self.read_requirements(
                    &path.parent().unwrap_or(Path::new(".")).join(file),
                    constraint || mode,
                    visited,
                )?;
                continue;
            }
            if line.starts_with("--") {
                continue;
            }
            let expanded = crate::utils::context_resolver::interpolate_variables(line, &properties);
            let req = parse_requirement(&expanded).with_context(|| path.display().to_string())?;
            if constraint {
                self.constraints.push(req);
            } else {
                self.roots.push(req);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_requirements_preserve_includes_constraints_markers_and_extras() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/test_outputs/python_requirement_loader");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("requirements.txt"),
            "-r base.txt\n-c pins.txt\nclient[socks]>=1 ; sys_platform == 'win32'\n",
        )
        .unwrap();
        fs::write(
            dir.join("base.txt"),
            "-r requirements.txt\ntransport==2 \\\n --hash=sha256:abc\n",
        )
        .unwrap();
        fs::write(dir.join("pins.txt"), "client<3\n").unwrap();
        fs::write(dir.join("pyproject.toml"), "[project]\nname='app'\ndependencies=['extra-package>=1']\n[project.optional-dependencies]\ntest=['not-selected']\n").unwrap();
        let requirements = ProjectRequirements::load(&dir).unwrap();
        assert_eq!(requirements.roots.len(), 3);
        assert_eq!(requirements.constraints.len(), 1);
        let client = requirements
            .roots
            .iter()
            .find(|r| r.name.as_ref() == "client")
            .unwrap();
        assert_eq!(client.extras[0].as_ref(), "socks");
        assert!(!client.marker.is_true());
        assert!(requirements
            .roots
            .iter()
            .all(|r| r.name.as_ref() != "not-selected"));
        fs::write(dir.join("requirements.txt"), "-r missing.txt\n").unwrap();
        assert!(ProjectRequirements::load(&dir).is_err());
    }
    #[test]
    fn poetry_shorthand_obeys_zero_major_and_tilde_rules() {
        for (raw, yes, no) in [
            ("^0.2.3", "0.2.9", "0.3.0"),
            ("~1.2", "1.2.9", "1.3.0"),
            ("^1.2", "1.9", "2.0"),
        ] {
            let req = parse_requirement(&format!("demo{}", poetry_spec(raw).unwrap())).unwrap();
            assert!(version_matches(&req, yes).unwrap());
            assert!(!version_matches(&req, no).unwrap());
        }
    }
}
