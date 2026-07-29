#!/usr/bin/env python

import json
import sys

if len(sys.argv) != 3:
    print("pass two files in parameter")
    sys.exit(1)

first_file = sys.argv[1]
second_file = sys.argv[2]

def load_components(path: str):
    res = {}
    with open(path, 'r') as file:
        first_data = json.load(file)

        first_components = first_data.get("components")
        for component in first_components:
            name = component.get("name")
            type = component.get("type")
            version = component.get("version")
            purl = component.get("purl")
            if type == "library" and purl is not None and "maven" in purl:
                res[name] = version

    return res

first_file_components = load_components(first_file)
second_file_components = load_components(second_file)

errors = 0

## Let's find components common two both with different versions
for name, version in first_file_components.items():
    if name in second_file_components and version != second_file_components[name]:
        print(f"Component {name} has different versions: {version} (in {first_file}) and {second_file_components[name]} (in {second_file})")
        errors = errors + 1


## Let's find components in the first file absent from the second
for name, version in first_file_components.items():
    if name not in second_file_components:
        print(f"Component {name} is in the first file ({first_file}) but not in the second ({second_file})")
        errors = errors + 1

## Let's find components in the second file absent from the first
for name, version in second_file_components.items():
    if name not in first_file_components:
        print(f"Component {name} is in the second file ({second_file}) but not in the first ({first_file})")
        errors = errors + 1

max_components = max(len(first_file_components), len(second_file_components))
if errors > 0:
    accuracy = (abs(max_components - errors)/max_components) * 100
    print(f"{errors} errors found, tool accuracy {accuracy:.2f} (first file has {len(first_file_components)} components, second file has {len(second_file_components)} components)")
    sys.exit(errors)

print("no error found")
sys.exit(0)