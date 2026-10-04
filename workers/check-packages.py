#!/usr/bin/env python3
"""Compile extracted Workers owner packages with extracted private Capability deps.

Requires Python 3.12+, Node.js and the wasm32-unknown-unknown Rust target. CARGO accepts a
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
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
CARGO = shlex.split(os.environ.get("CARGO", "cargo"))
OWNERS = {
    "account": ("account-admin", "auth-delegation", "credential-state", "managed-session", "operator-binding"), "oauth-flow": ("oauth-flow",),
    "password": ("credential-issuer", "identity-directory", "password-auth", "managed-session"),
    "session-renewal": ("managed-session",),
    "operator-session": ("operator-binding", "operator-session", "credential-issuer", "credential-state", "auth"),
    "phone": ("credential-issuer", "identity-directory", "phone-auth", "sms-delivery"),
    "device": ("device-auth",), "api-token": ("auth", "credential-state", "api-token-admin"),
    "oidc": ("credential-issuer", "identity-directory", "oidc-provider"),
}
selected = os.environ.get("LENSO_AUTH_PACKAGE_OWNERS")
if selected:
    names = selected.split(",")
    if len(set(names)) != len(names) or any(name not in OWNERS for name in names):
        raise SystemExit("LENSO_AUTH_PACKAGE_OWNERS must contain distinct supported owner names")
    OWNERS = {name: OWNERS[name] for name in names}
CAPABILITIES = tuple(sorted({name for dependencies in OWNERS.values() for name in dependencies}))


def cargo(*args, capture=False):
    return subprocess.run(
        [*CARGO, *map(str, args)], cwd=ROOT, check=True,
        text=True, stdout=subprocess.PIPE if capture else None,
    ).stdout


subprocess.run(["node", str(ROOT / "workers/generate-bridges.mjs"), "--check"], check=True)
subprocess.run([sys.executable, str(ROOT / "workers/generate-migrations.py"), "--check"], check=True)

with tempfile.TemporaryDirectory(prefix="lenso-auth-packages-") as temporary:
    task = Path(temporary)
    staging = task / "source"
    staging.mkdir()
    # Package from isolated inputs so temporary registry patches cannot rewrite
    # the repository lockfile. Deliberately exclude the repository workers/ tree.
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copy2(ROOT / name, staging / name)
    shutil.copytree(ROOT / "crates", staging / "crates", ignore=shutil.ignore_patterns("target"))
    # The Native-only human facade is a separate source consumer. Resolving its
    # Git-backed RBAC dev graph while patching an extracted SDK would collide
    # with the SDK workspace member, outside this Workers artifact cohort.
    workspace = staging / "Cargo.toml"
    workspace.write_text(workspace.read_text().replace(
        '    "crates/lenso-auth-human-api-token-plugin",\n', ""))
    archives = task / "artifacts"
    extracted = task / "extracted"
    extracted.mkdir()
    versions = {}
    runtime_packages = {}
    # Optional unpublished dependency cohort (Runtime or migration kits), supplied
    # as real archives, never source paths. Patches also apply during Capability
    # packaging because Cargo resolves the complete staged workspace.
    for archive in filter(None, os.environ.get("RUNTIME_ARCHIVES", "").split(os.pathsep)):
        with tarfile.open(archive) as packed:
            packed.extractall(extracted, filter="data")
        directory = extracted / Path(archive).name.removesuffix(".crate")
        name = tomllib.loads((directory / "Cargo.toml").read_text())["package"]["name"]
        runtime_packages[name] = directory

    if "operator-session" in OWNERS:
        # Cargo normalizes Git dependencies to registry versions in .crate files.
        # Stage the operator's unpublished Roles as real archives from exactly
        # the locked Git objects; never patch the extracted graph to source trees.
        graph = json.loads(cargo("metadata", "--locked", "--format-version", "1", capture=True))
        manifest = ROOT / "crates/lenso-auth-operator-session-plugin/Cargo.toml"
        dependencies = tomllib.loads(manifest.read_text())["dependencies"]
        snapshots = {}
        for name in ("lenso-capability-access-control", "lenso-capability-access-control-admin",
                     "lenso-capability-audit-log"):
            declared = dependencies[name]
            source = f'git+{declared["git"]}?rev={declared["rev"]}#{declared["rev"]}'
            candidates = [package for package in graph["packages"]
                          if package["name"] == name and package["source"] == source
                          and package["version"] == declared["version"]]
            assert len(candidates) == 1, f"{name}: expected exact locked Git Role"
            dependency = candidates[0]
            if name in runtime_packages:
                packed = tomllib.loads((runtime_packages[name] / "Cargo.toml").read_text())["package"]
                assert packed["version"] == dependency["version"], f"{name}: supplied archive version drift"
                continue
            cached_manifest = Path(dependency["manifest_path"])
            repository = Path(subprocess.check_output(
                ["git", "-C", str(cached_manifest.parent), "rev-parse", "--show-toplevel"], text=True).strip())
            key = (repository, declared["rev"])
            if key not in snapshots:
                snapshot = task / f"git-role-source-{len(snapshots)}"
                snapshot.mkdir()
                archive = task / f"git-role-source-{len(snapshots)}.tar"
                subprocess.run(["git", "-C", str(repository), "archive", "--format=tar",
                                f"--output={archive}", declared["rev"]], check=True)
                with tarfile.open(archive) as packed:
                    packed.extractall(snapshot, filter="data")
                snapshots[key] = snapshot
            isolated_manifest = snapshots[key] / cached_manifest.relative_to(repository)
            cargo("package", "--manifest-path", isolated_manifest, "--no-verify",
                  "--allow-dirty", "--target-dir", archives)
            archive = archives / "package" / f'{name}-{dependency["version"]}.crate'
            with tarfile.open(archive) as packed:
                packed.extractall(extracted, filter="data")
            runtime_packages[name] = extracted / archive.name.removesuffix(".crate")
            print(f"STAGED: {name} {dependency['version']} from {source}", flush=True)

    cohort_config = task / "cohort-patch.toml"
    cohort_config.write_text("[patch.crates-io]\n" + "".join(
        f'{name} = {{ path = {json.dumps(str(directory))} }}\n'
        for name, directory in runtime_packages.items()))

    def package(name, config=cohort_config, workers=False):
        manifest = staging / "crates" / name / "Cargo.toml"
        versions[name] = tomllib.loads(manifest.read_text())["package"]["version"]
        args = ["package", "--manifest-path", manifest, "--no-verify", "--allow-dirty",
                "--target-dir", archives]
        args += ["--config", config]
        if workers:
            args += ["--no-default-features", "--features", "workers"]
        cargo(*args)
        archive = archives / "package" / f"{name}-{versions[name]}.crate"
        with tarfile.open(archive) as packed:
            packed.extractall(extracted, filter="data")
        return extracted / f"{name}-{versions[name]}"

    runtime_packages["lenso-auth-sdk"] = package("lenso-auth-sdk")
    cohort_config.write_text("[patch.crates-io]\n" + "".join(
        f'{name} = {{ path = {json.dumps(str(directory))} }}\n'
        for name, directory in runtime_packages.items()))
    capabilities = {name: package(f"lenso-capability-{name}") for name in CAPABILITIES}
    for owner, dependencies in OWNERS.items():
        config = task / f"{owner}-patch.toml"
        config.write_text("[patch.crates-io]\n" + "".join(
            f'lenso-capability-{name} = {{ path = {json.dumps(str(capabilities[name]))} }}\n'
            for name in dependencies
        ) + "".join(f'{name} = {{ path = {json.dumps(str(directory))} }}\n'
                    for name, directory in runtime_packages.items()))
        name = f"lenso-auth-{owner}-plugin"
        directory = package(name, config, workers=True)
        source = ROOT / "crates" / name
        if owner not in {"session-renewal", "operator-session"}:
            for relative in ("src/workers.rs", "src/migration.rs"):
                assert (directory / relative).read_bytes() == (source / relative).read_bytes(), relative
            for backend in ("postgres", "d1"):
                relative = Path("migrations") / backend
                expected = {sql.relative_to(source): sql.read_bytes()
                            for sql in (source / relative).rglob("*.sql")}
                packaged = {sql.relative_to(directory): sql.read_bytes()
                            for sql in (directory / relative).rglob("*.sql")}
                assert expected and packaged == expected, f"{name}: {backend} migration archive drift"
        args = ["--manifest-path", directory / "Cargo.toml", "--locked",
                "--no-default-features", "--features", "workers", "--config", config]
        cargo("check", *args, "--target", "wasm32-unknown-unknown")
        graph = json.loads(cargo("metadata", *args, "--format-version", "1", capture=True))
        # Every non-registry package in this graph must come from an archive.
        for dependency in graph["packages"]:
            if dependency["source"] is None:
                assert Path(dependency["manifest_path"]).is_relative_to(extracted), dependency["name"]
        print(f"PASS: extracted {name} Workers wasm package; owned files and all local dependencies are archives", flush=True)
