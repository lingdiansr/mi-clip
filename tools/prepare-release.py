"""Set the Cargo package and lockfile version in a release checkout."""

import re
import sys
import tomllib
from pathlib import Path


def prepare_release(version):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise SystemExit('Use a stable release version such as 0.2.0.')

    manifest_path = Path('Cargo.toml')
    lock_path = Path('Cargo.lock')
    manifest_text = manifest_path.read_text()
    lock_text = lock_path.read_text()
    package_name = tomllib.loads(manifest_text)['package']['name']

    def replace_version(section):
        updated, count = re.subn(
            r'(?m)^version\s*=\s*"[^"\n]+"',
            f'version = "{version}"',
            section,
        )
        if count != 1:
            raise SystemExit('Expected exactly one package version field.')
        return updated

    # Preserve formatting and all dependency versions in both files.
    manifest_sections = re.split(r'(?m)(?=^\[)', manifest_text)
    for index, section in enumerate(manifest_sections):
        if section.startswith('[package]\n'):
            manifest_sections[index] = replace_version(section)
    updated_manifest = ''.join(manifest_sections)

    lock_sections = re.split(r'(?m)(?=^\[\[package\]\])', lock_text)
    matches = 0
    for index, section in enumerate(lock_sections):
        if not section.startswith('[[package]]'):
            continue
        package = tomllib.loads(section)['package'][0]
        if package['name'] == package_name and 'source' not in package:
            lock_sections[index] = replace_version(section)
            matches += 1
    if matches != 1:
        raise SystemExit('Expected exactly one local package in Cargo.lock.')
    if tomllib.loads(updated_manifest)['package']['version'] != version:
        raise SystemExit('Could not update Cargo.toml package version.')

    manifest_path.write_text(updated_manifest)
    lock_path.write_text(''.join(lock_sections))
    print(f'Set {package_name} release version to {version}.')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 tools/prepare-release.py VERSION')
    prepare_release(sys.argv[1])
