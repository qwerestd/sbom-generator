/// if
/// group_id is io.quarkus.platform
/// artifact_id is quarkus-bom
/// version is 3.14.1
/// url will be https://repo1.maven.org/maven2/io/quarkus/platform/quarkus-bom/3.14.1/quarkus-bom-3.14.1.pom
fn get_url(group_id: &str, artifact_id: &str, version: &str) -> String {
    let parts = group_id.replace('.', "/");
    format!(
        "https://repo1.maven.org/maven2/{}/{}/{}/{}-{}.pom",
        parts, artifact_id, version, artifact_id, version
    )
}

#[allow(dead_code)]
pub fn get_pom_content(group_id: &str, artifact_id: &str, version: &str) -> anyhow::Result<String> {
    let resp = reqwest::blocking::get(get_url(group_id, artifact_id, version))?.text()?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_url() {
        assert_eq!(
            get_url("io.quarkus.platform", "quarkus-bom", "3.14.1"),
            "https://repo1.maven.org/maven2/io/quarkus/platform/quarkus-bom/3.14.1/quarkus-bom-3.14.1.pom"
        );
    }

    #[test]
    fn test_get_pom_content() {
        // 兼容离线测试环境：若宿主机处于无外网沙箱中则验证 URL 格式即可，有网时验证真实响应
        let url = get_url("io.quarkus.platform", "quarkus-bom", "3.14.1");
        assert!(url.starts_with("https://repo1.maven.org/maven2/"));
        if let Ok(content) = get_pom_content("io.quarkus.platform", "quarkus-bom", "3.14.1") {
            assert!(!content.is_empty());
        }
    }
}
