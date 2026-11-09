"""Offline CLI experiment against hand-written synthetic dependency ground truth."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def score(expected, actual):
    tp = sum((expected & actual).values())
    fp = sum((actual - expected).values())
    fn = sum((expected - actual).values())
    return dict(tp=tp, fp=fp, fn=fn,
                precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None)


def run_case(case, exe, output_dir):
    truth = json.loads((case / 'expected.json').read_text(encoding='utf-8'))
    dest = output_dir / (case.name + '.json')
    sentinel = 'previous output must survive failed scan'
    dest.write_text(sentinel, encoding='utf-8')
    cmd = [str(exe), '-i', str(case), '-o', str(dest)]
    env = os.environ.copy()
    if truth.get('missing_manager'):
        (case / 'node_modules').mkdir(exist_ok=True)
        # Only this child process loses PATH. npm's applicability is forced by
        # the fixture's node_modules directory; no real manager is executed.
        env['PATH'] = ''
    else:
        cmd.append('-s')
    result = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                            encoding='utf-8', errors='replace', timeout=45)
    (output_dir / (case.name + '.log')).write_text(
        result.stdout + '\nSTDERR:\n' + result.stderr, encoding='utf-8')
    errors = []
    row = dict(case=case.name, exit_code=result.returncode)
    if truth.get('expect_failure'):
        if result.returncode == 0 or dest.read_text(encoding='utf-8') != sentinel:
            errors.append('Invalid manifest must fail and preserve previous output')
        row.update(passed=not errors, errors=errors)
        return row
    if result.returncode:
        return dict(row, passed=False, errors=['CLI failed: ' + result.stderr])
    bom = json.loads(dest.read_text(encoding='utf-8'))
    cs = bom['components']
    by_ref = {c['bom-ref']: c for c in cs}
    if len(by_ref) != len(cs):
        errors.append('Duplicate bom-ref')
    actual_libs = Counter(c['purl'] for c in cs if c['type'] == 'library')
    actual_apps = Counter(c['purl'] for c in cs if c['type'] == 'application')
    expected_libs = Counter(truth['libraries'])
    expected_apps = Counter(truth['applications'])
    actual_edges = Counter()
    actual_scoped_edges = Counter()
    def source_path(c):
        return next((p['value'].replace('\\', '/') for p in c.get('properties', [])
                     if p['name'].endswith(':path')), '')
    for node in bom['dependencies']:
        source = by_ref.get(node['ref'])
        if source is None:
            errors.append('Unknown dependency source: ' + node['ref'])
            continue
        for target_ref in node.get('dependsOn', []):
            target = by_ref.get(target_ref)
            if target is None:
                errors.append('Dangling dependency target: ' + target_ref)
                continue
            actual_edges[(source['purl'], target['purl'])] += 1
            actual_scoped_edges[(source['purl'], source_path(source),
                                 target['purl'], source_path(target))] += 1
            if truth.get('same_source_edges'):
                def paths(c):
                    return {p['value'] for p in c.get('properties', [])
                            if p['name'].endswith(':path')}
                if not paths(source) or paths(source) != paths(target):
                    errors.append('Cross-project edge or missing source path')
    expected_edges = Counter(tuple(e) for e in truth['edges'])
    if 'scoped_edges' in truth:
        expected_scoped_edges = Counter(tuple(e) for e in truth['scoped_edges'])
        row['scoped_edges'] = score(expected_scoped_edges, actual_scoped_edges)
        row['scoped_edges']['missing'] = [str(x) for x in (expected_scoped_edges - actual_scoped_edges).elements()]
        row['scoped_edges']['extra'] = [str(x) for x in (actual_scoped_edges - expected_scoped_edges).elements()]
        if expected_scoped_edges != actual_scoped_edges:
            errors.append('Source-qualified instance edges differ from ground truth')
    for label, expected, actual in [('libraries', expected_libs, actual_libs),
                                     ('applications', expected_apps, actual_apps),
                                     ('edges', expected_edges, actual_edges)]:
        row[label] = score(expected, actual)
        row[label]['missing'] = [str(x) for x in (expected - actual).elements()]
        row[label]['extra'] = [str(x) for x in (actual - expected).elements()]
        if expected != actual:
            errors.append(label + ' differs from ground truth')
    for purl, req in truth.get('requirements', {}).items():
        matches = [c for c in cs if c['purl'] == purl]
        if len(matches) != 1 or matches[0].get('version') or not any(
                p['name'] == 'sbom:version:requirement' and p['value'] == req
                for p in matches[0].get('properties', [])):
            errors.append('Incorrect unresolved version/requirement: ' + purl)
    if truth.get('stderr_contains') and truth['stderr_contains'] not in result.stderr:
        errors.append('Missing fallback warning')
    if truth.get('missing_manager') and not (
            '[NPM]' in result.stderr and '动态探测受挫' in result.stderr):
        errors.append('Missing evidence of failed npm dynamic probe')
    if not all(any(p['name'].endswith(':path') for p in c.get('properties', []))
               for c in cs):
        errors.append('Component missing source location')
    row.update(passed=not errors, errors=errors)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=ROOT / 'target/debug' /
                        ('sbom-generator.exe' if os.name == 'nt' else 'sbom-generator'))
    args = parser.parse_args()
    output = ROOT / 'target/test_outputs/controlled'
    output.mkdir(parents=True, exist_ok=True)
    rows = [run_case(p, args.exe.resolve(), output)
            for p in sorted((ROOT / 'test/controlled').iterdir())
            if p.is_dir() and (p / 'expected.json').exists()]
    (ROOT / 'test/controlled/results.json').write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    provenance = dict(
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        executable=str(args.exe.resolve()),
        executable_sha256=hashlib.sha256(args.exe.read_bytes()).hexdigest(),
        mode='static-only except case 06: dynamic enabled, child PATH empty',
        input_sha256={str(p.relative_to(ROOT)).replace('\\', '/'):
                      hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted((ROOT / 'test/controlled').rglob('*'))
                      if p.is_file() and p.relative_to(ROOT / 'test/controlled').parts[0][:2].isdigit()})
    (ROOT / 'test/controlled/provenance.json').write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# Controlled SBOM correctness experiment', '',
             'Ground truth is hand-written in each expected.json, before running the generator.',
             'Synthetic package names; no installation, registry access, or runtime execution.',
             'Components are scored as (PURL, type) multisets; edges as directed PURL-pair multisets.',
             'Unresolved identities are included and checked separately; no placeholder-version filtering.',
             'Library counts include unresolved identities, not just exact-version packages.', '',
             '| Case | Result | Library TP/FP/FN | Application TP/FP/FN | Edge TP/FP/FN |',
             '|---|---|---|---|---|']
    for row in rows:
        cells = [row['case'], 'PASS' if row['passed'] else 'FAIL']
        for k in ['libraries', 'applications', 'edges']:
            s = row.get(k)
            cells.append('/'.join(str(s[n]) for n in ['tp', 'fp', 'fn']) if s else 'N/A')
        lines.append('| ' + ' | '.join(cells) + ' |')
    lines += ['', '## Micro totals', '']
    for label in ['libraries', 'applications', 'edges']:
        totals = {n: sum(r.get(label, {}).get(n, 0) for r in rows)
                  for n in ['tp', 'fp', 'fn']}
        tp, fp, fn = (totals[n] for n in ['tp', 'fp', 'fn'])
        lines.append(f'- {label}: TP={tp}, FP={fp}, FN={fn}; '
                     f'precision={tp/(tp+fp):.2%}, recall={tp/(tp+fn):.2%}.')
    for row in rows:
        if not row['passed']:
            lines += ['', '## ' + row['case'], '', '```json',
                      json.dumps(row, ensure_ascii=False, indent=2), '```']
    lines += ['', 'Outputs and process logs: target/test_outputs/controlled.',
              'These small designed cases do not establish real-world accuracy or runtime reachability.',
              'Schema/PURL verification is a separate Rust integration test: controlled_schema.']
    (ROOT / 'test/controlled/report.md').write_text('\n'.join(lines), encoding='utf-8')
    for row in rows:
        print(('PASS ' if row['passed'] else 'FAIL ') + row['case'] + ': ' + '; '.join(row['errors']))
    return 0 if rows and all(r['passed'] for r in rows) else 1


if __name__ == '__main__':
    sys.exit(main())
