#!/usr/bin/env python3
"""Compile extracted Workers owner packages with extracted private Capability deps.

Requires Python 3.12+ and the wasm32-unknown-unknown Rust target. CARGO accepts a
command, e.g. '/path/to/lenso-cargo +1.94.0'. No registry publication occurs.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
CARGO = shlex.split(os.environ.get("CARGO", "cargo"))
OWNERS = {
    "account": ("account-admin", "auth-delegation"), "oauth-flow": ("oauth-flow",),
    "password": ("credential-issuer", "identity-directory", "password-auth"),
    "phone": ("credential-issuer", "identity-directory", "phone-auth", "sms-delivery"),
    "device": ("device-auth",), "api-token": ("auth",),
    "oidc": ("credential-issuer", "identity-directory", "oidc-provider"),
}
CAPABILITIES = tuple(sorted({name for dependencies in OWNERS.values() for name in dependencies}))


def cargo(*args, capture=False):
    return subprocess.run(
        [*CARGO, *map(str, args)], cwd=ROOT, check=True,
        text=True, stdout=subprocess.PIPE if capture else None,
    ).stdout


with tempfile.TemporaryDirectory(prefix="lenso-auth-packages-") as temporary:
    task = Path(temporary)
    staging = task / "source"
    staging.mkdir()
    # Package from isolated inputs so temporary registry patches cannot rewrite
    # the repository lockfile. Deliberately exclude the repository workers/ tree.
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copy2(ROOT / name, staging / name)
    shutil.copytree(ROOT / "crates", staging / "crates", ignore=shutil.ignore_patterns("target"))
    archives = task / "artifacts"
    extracted = task / "extracted"
    extracted.mkdir()
    versions = {}
    runtime_packages = {}
    # Optional unpublished Runtime cohort, supplied as real archives, never source paths.
    for archive in filter(None, os.environ.get("RUNTIME_ARCHIVES", "").split(os.pathsep)):
        with tarfile.open(archive) as packed:
            packed.extractall(extracted, filter="data")
        directory = extracted / Path(archive).name.removesuffix(".crate")
        name = tomllib.loads((directory / "Cargo.toml").read_text())["package"]["name"]
        runtime_packages[name] = directory

    def package(name, config=None):
        manifest = staging / "crates" / name / "Cargo.toml"
        versions[name] = tomllib.loads(manifest.read_text())["package"]["version"]
        args = ["package", "--manifest-path", manifest, "--no-verify", "--allow-dirty",
                "--target-dir", archives]
        if config:
            args += ["--no-default-features", "--features", "workers", "--config", config]
        cargo(*args)
        archive = archives / "package" / f"{name}-{versions[name]}.crate"
        with tarfile.open(archive) as packed:
            packed.extractall(extracted, filter="data")
        return extracted / f"{name}-{versions[name]}"

    capabilities = {name: package(f"lenso-capability-{name}") for name in CAPABILITIES}
    for owner, dependencies in OWNERS.items():
        config = task / f"{owner}-patch.toml"
        config.write_text("[patch.crates-io]\n" + "".join(
            f'lenso-capability-{name} = {{ path = {json.dumps(str(capabilities[name]))} }}\n'
            for name in dependencies
        ) + "".join(f'{name} = {{ path = {json.dumps(str(directory))} }}\n'
                    for name, directory in runtime_packages.items()))
        name = f"lenso-auth-{owner}-plugin"
        directory = package(name, config)
        assert (directory / "src/workers.rs").read_bytes() == (ROOT / "workers/d1.rs").read_bytes()
        args = ["--manifest-path", directory / "Cargo.toml", "--locked",
                "--no-default-features", "--features", "workers", "--config", config]
        cargo("check", *args, "--target", "wasm32-unknown-unknown")
        graph = json.loads(cargo("metadata", *args, "--format-version", "1", capture=True))
        # Every non-registry package in this graph must come from an archive.
        for dependency in graph["packages"]:
            if dependency["source"] is None:
                assert Path(dependency["manifest_path"]).is_relative_to(extracted), dependency["name"]
        print(f"PASS: extracted {name} Workers wasm package; all local dependencies are archives", flush=True)
