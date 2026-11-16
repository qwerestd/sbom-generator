# Python and Go dependency probing

Dynamic analysis queries package managers. It does not imply application execution,
installation, runtime loading, or complete dependency coverage. Static declarations
remain available alongside successful or partial dynamic evidence.

## Python

The generator first runs `python -I -X utf8 -m pip inspect` against a selected
interpreter. Only packages reachable from compatible declared roots and active
extras are admitted. Unrelated environment packages are not attributed to a
project. Version and source constraints remain enforced.

If the installed environment cannot satisfy the project, dynamic mode attempts
`pip install --dry-run --ignore-installed --only-binary=:all: --report -`.
This resolves available wheel metadata without installing packages or building
source distributions. Local paths, VCS requirements and direct URLs are not
automatically built. Resolution depends on the selected Python version, platform,
configured indexes, network and available wheels. A recent pip supporting inspect,
dry-run and report is required.

Resolved results use `sbom:analysis:method=pip-resolve-report` and
`sbom:python:installed-evidence=false`. They are resolution evidence, not an
assertion of installation. Available download metadata is retained. If resolution
fails, compatible reachable installed packages can still be returned with
`sbom:analysis:status=partial`, missing-dependency diagnostics and closed references.
No matching root means static fallback, not an inventory of the entire interpreter.

### Interpreter selection

```powershell
sbom-generator -i C:\projects\service -o result.json --python-executable C:\envs\service\Scripts\python.exe
sbom-generator -i C:\projects\repo -o result.json --python-env-map C:\config\python-envs.json
sbom-generator -i C:\projects\repo -o result.json --no-python-resolve
```

Environment map format:

```json
{
  "C:/projects/repo": "C:/envs/shared/Scripts/python.exe",
  "C:/projects/repo/services/api": "C:/envs/api/Scripts/python.exe"
}
```

The longest matching project prefix wins. Relative map keys and interpreter paths
are interpreted relative to the mapping file. Explicit maps and executable options
are trusted user selections. Without these, active `VIRTUAL_ENV` / `CONDA_PREFIX`
and host Python discovery are used; executables inside a scanned `.venv` are not
automatically executed.

Equivalent environment variables:

| Variable | Behavior |
| --- | --- |
| `SBOM_PYTHON_EXECUTABLE` | Explicit interpreter file |
| `SBOM_PYTHON_ENV_MAP` | JSON environment-map file |
| `SBOM_PYTHON_RESOLVE=0` | Disable wheel-only resolution |
| `SBOM_PYTHON_TIMEOUT` | Inspection budget in seconds, default 30 |
| `SBOM_PYTHON_RESOLVE_TIMEOUT` | Resolution budget in seconds, default 120 |

Inspection is shared for one interpreter during a scan. Resolution results are
cached by interpreter, requirements and constraints, avoiding identical repeated
queries across services. Neither operation installs project dependencies.

## Go

The generator recognizes the nearest `go.work` for participating member modules.
`SBOM_GO_WORKSPACE=off` disables workspace use, while an absolute path selects an
explicit file. Otherwise an explicit `GOWORK` selection is respected before automatic
discovery. Independent tool modules not listed in the workspace are analyzed on
their own.

Missing workspace members are recorded. Available members may be queried through a
temporary workspace containing absolute paths, preserving replacements and adding
version-specific local replacements for known workspace member requirements. This
avoids remote lookups of unpublished local placeholder versions. The original
`go.work` and `go.mod` files are not rewritten. Missing-member results remain partial;
the absent modules are not invented. Temporary workspace and sum files are removed
when their context is dropped.

Module graph and selected-module queries run independently. One successful source
is retained even if the other fails. A graph without a selected module list is
marked as requirement-only evidence, not a confirmed selected inventory. A selected
module list can be combined with native manifest declarations for direct edges when
the full graph is unavailable; transitive edges are not guessed.

Source imports use `go list -e -mod=readonly -deps -json ./...`. Incomplete packages
are diagnosed; verified package relationships can coexist with retained module
evidence. Tool-only modules with no ordinary packages are marked not applicable
for import analysis. Workspace evidence is scoped back to the current project and
its reachable module/import relationships, excluding unrelated workspace members.
Shared workspace module queries are cached within one scan.

| Variable | Behavior |
| --- | --- |
| `SBOM_GO_WORKSPACE` | `off`, `auto`, or an explicit workspace path |
| `SBOM_GO_MOD_TIMEOUT` | Module-query budget, default 60 seconds |
| `SBOM_GO_IMPORT_TIMEOUT` | Import-query budget, default 120 seconds; 0 skips imports |
| `SBOM_GO_TIMEOUT` | Common budget when a stage-specific value is absent |
| `SBOM_GO_INCLUDE_TESTS=1` | Include test imports; disabled by default |

Module inventories may still contain build or test requirements even when test
imports are disabled. Neither module presence nor an import proves runtime loading.

## Diagnostics and validation

Successful and partial probes have separate diagnostic statuses. Partial evidence
is retained, but does not mark a project fully resolved. Component properties and
the `.scan.json` sidecar record methods, issues, scope and environment evidence.

```powershell
cargo test --locked --offline --lib
cargo test --locked --offline --test dynamic_improvements -- --nocapture
cargo test --locked --offline --test controlled_schema
cargo clippy --locked --offline --lib --bin sbom-generator --tests -- -D warnings
```

The native integration cases use a local Go workspace with a deliberately missing
member and hand-built local wheel fixtures. They exercise the real Go/pip commands
offline and check that inputs remain unchanged, unrelated components are excluded,
references remain closed, and pip resolution does not install the fixture packages.
They are designed tests, not real-project accuracy measurements. If a required
tool is unavailable, the integration test prints that it was not exercised.
