import json
import os

def load_json(file_path):
    if not os.path.exists(file_path):
        print(f"错误: 找不到文件 {file_path}")
        return None
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_components(bom_data):
    """提取所有含有 PURL 的组件信息"""
    components_dict = {}
    components = bom_data.get("components", [])

    # 兼容处理 CycloneDX 1.6 和 1.7 的 tools 结构差异
    for comp in components:
        purl = comp.get("purl")
        if purl:
            components_dict[purl] = {
                "group": comp.get("group", ""),
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "type": comp.get("type", "")
            }
    return components_dict

def analyze_dependencies(bom_data):
    """分析依赖关系数量"""
    dependencies = bom_data.get("dependencies", [])
    total_relations = 0
    for dep in dependencies:
        total_relations += len(dep.get("dependsOn", []))
    return len(dependencies), total_relations

def main():
    sbom_file = "sbom.json"
    trivy_file = "trivy.json"

    sbom_data = load_json(sbom_file)
    trivy_data = load_json(trivy_file)

    if not sbom_data or not trivy_data:
        return

    # 提取组件
    sbom_comps = extract_components(sbom_data)
    trivy_comps = extract_components(trivy_data)

    sbom_set = set(sbom_comps.keys())
    trivy_set = set(trivy_comps.keys())

    # 计算集合关系
    shared_components = sbom_set.intersection(trivy_set)
    only_sbom = sbom_set - trivy_set
    only_trivy = trivy_set - sbom_set

    # 依赖关系分析
    sbom_nodes, sbom_edges = analyze_dependencies(sbom_data)
    trivy_nodes, trivy_edges = analyze_dependencies(trivy_data)

    # 打印可视化报表
    print("=" * 70)
    print("          SBOM GENERATOR VS AQUA TRIVY DETAILED COMPARISON")
    print("=" * 70)

    print(f"{'Analysis Metric (分析指标)':<40} | {'Our Tool (SBOM)':<12} | {'Trivy Baseline':<12}")
    print("-" * 70)
    print(f"{'Total Library Components (Total PURLs)':<40} | {len(sbom_comps):<12} | {len(trivy_comps):<12}")
    print(f"{'Dependency Graph Nodes (声明依赖库)':<40} | {sbom_nodes:<12} | {trivy_nodes:<12}")
    print(f"{'Dependency Graph Edges (直接+透传依赖链)':<40} | {sbom_edges:<12} | {trivy_edges:<12}")
    print("-" * 70)

    print(f"\n[+] Shared Components (双方共同检出): {len(shared_components)}")
    print(f"[+] Unique to Our Tool (我方工具独有 - 提升召回率): {len(only_sbom)}")
    print(f"[+] Unique to Trivy (Trivy 独有): {len(only_trivy)}")

    # 详细列出我方工具高召回率的具体组件（用于论文中证明 Static Producer + Dynamic Probe 的优势）
    if only_sbom:
        print("\n" + "─" * 20 + " 💡 DETAILED OVER-RECALL (UNIQUE TO OUR TOOL) " + "─" * 20)
        print(f"{'Component PURL':<55} | {'Version':<10}")
        print("-" * 70)
        # 按 group 排序打印，方便归类展示
        for purl in sorted(only_sbom):
            print(f"{purl:<55} | {sbom_comps[purl]['version']:<10}")

    if only_trivy:
        print("\n" + "─" * 20 + " 🔍 UNIQUE TO TRIVY " + "─" * 20)
        for purl in sorted(only_trivy):
            print(f" - {purl}")

if __name__ == "__main__":
    main()