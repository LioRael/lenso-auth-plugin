import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { tmpdir } from "node:os";

import {
  captureWorktreeSnapshot,
  loadMatrix,
  requireCurrentSource,
  requireQualified,
  summarizeReceipt,
  validateMatrix,
  validateReceipt,
} from "./oauth-conformance.mjs";

const loadedMatrix = loadMatrix(new URL("./oauth-conformance.matrix.json", import.meta.url));
const { matrix } = loadedMatrix;

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}

function sourceSnapshot(state = "clean") {
  return {
    base_revision: "0".repeat(40),
    worktree_snapshot: {
      schema: "lenso.git-worktree-snapshot@1",
      state,
      sha256: digest("a"),
      tracked_diff_sha256: digest("b"),
      untracked_file_count: state === "dirty" ? 1 : 0,
      untracked_content_sha256: digest("c"),
    },
  };
}

function business(composition, status = "passed") {
  return Object.fromEntries(
    composition.business_invariant_ids.map((invariant) => [invariant, status]),
  );
}

function qualifiedRun(composition) {
  const target = composition.required_qualification_level === "target";
  return {
    composition_id: composition.id,
    business_invariants: business(composition),
    qualification: {
      level: target ? "target" : "local",
      status: "passed",
      satisfied_requirement_ids: [...composition.qualification_requirements],
      pending_requirement_ids: [],
    },
    evidence: [
      {
        kind: "test-fixture",
        scope: target ? "actual-target" : "local",
        reference: `test-${composition.id}`,
      },
    ],
  };
}

function qualifiedReceipt() {
  const receipt = {
    schema: "lenso.auth.oauth-flow-conformance-receipt@1",
    matrix_schema: matrix.schema,
    matrix_digest: loadedMatrix.digest,
    scenario_id: matrix.scenario.id,
    source: sourceSnapshot(),
    runs: matrix.compositions.map(qualifiedRun),
  };
  receipt.summary = summarizeReceipt(receipt);
  return receipt;
}

test("a complete clean candidate has separate passing business and target qualifications", () => {
  const receipt = qualifiedReceipt();
  assert.deepEqual(receipt.summary, {
    business_conformance: "passed",
    qualification: "passed",
  });
  assert.doesNotThrow(() => validateReceipt(loadedMatrix, receipt));
  assert.doesNotThrow(() => requireQualified(receipt));
});

test("a local workerd callback cohort remains an incomplete target qualification", () => {
  const receipt = qualifiedReceipt();
  const run = receipt.runs.find(
    (entry) => entry.composition_id === "workers-hyperdrive-postgresql",
  );
  run.qualification = {
    level: "local",
    status: "passed",
    satisfied_requirement_ids: [],
    pending_requirement_ids: [...matrix.compositions.find(
      (entry) => entry.id === "workers-hyperdrive-postgresql",
    ).qualification_requirements],
  };
  run.evidence = [
    {
      kind: "command",
      scope: "local",
      reference: "workers-postgresql-local-workerd-cohort",
    },
  ];
  receipt.summary = summarizeReceipt(receipt);

  assert.deepEqual(receipt.summary, {
    business_conformance: "passed",
    qualification: "incomplete",
  });
  assert.doesNotThrow(() => validateReceipt(loadedMatrix, receipt));
  assert.throws(() => requireQualified(receipt), /qualification is incomplete/);
});

test("target status requires actual-target evidence", () => {
  const receipt = qualifiedReceipt();
  const run = receipt.runs.find((entry) => entry.composition_id === "workers-d1");
  run.evidence[0].scope = "local";
  assert.throws(() => validateReceipt(loadedMatrix, receipt), /actual target evidence/);
});

test("a target status cannot be produced from a dirty snapshot", () => {
  const receipt = qualifiedReceipt();
  receipt.source = sourceSnapshot("dirty");
  assert.throws(() => validateReceipt(loadedMatrix, receipt), /dirty worktree snapshot/);
});

test("a gate rejects a receipt that belongs to a different worktree snapshot", () => {
  const receipt = qualifiedReceipt();
  assert.throws(
    () => requireCurrentSource(receipt, sourceSnapshot("dirty")),
    /does not match the current worktree/,
  );
});

test("every composition must retain every common business invariant", () => {
  const corrupted = structuredClone(matrix);
  corrupted.compositions[0].business_invariant_ids.pop();
  assert.throws(() => validateMatrix(corrupted), /every common business invariant/);
});

test("the opt-in PostgreSQL reference is labelled as local evidence", () => {
  const nativePostgresql = matrix.compositions.find(
    (composition) => composition.id === "native-postgresql",
  );
  assert.equal(nativePostgresql.local_command.id, "local-native-postgresql");
  assert.equal(nativePostgresql.required_qualification_level, "target");
});

test("worktree snapshot distinguishes a clean base from tracked and untracked changes", () => {
  const repository = mkdtempSync(join(tmpdir(), "lenso-oauth-conformance-"));
  try {
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    execFileSync("git", ["config", "user.email", "oauth-test@example.invalid"], { cwd: repository });
    execFileSync("git", ["config", "user.name", "OAuth Conformance Test"], { cwd: repository });
    writeFileSync(join(repository, "tracked.txt"), "base\n");
    execFileSync("git", ["add", "tracked.txt"], { cwd: repository });
    execFileSync("git", ["commit", "--quiet", "-m", "base"], { cwd: repository });

    const clean = captureWorktreeSnapshot(repository);
    assert.equal(clean.worktree_snapshot.state, "clean");

    writeFileSync(join(repository, "tracked.txt"), "changed\n");
    writeFileSync(join(repository, "untracked.txt"), "candidate-only\n");
    const dirty = captureWorktreeSnapshot(repository);
    assert.equal(dirty.base_revision, clean.base_revision);
    assert.equal(dirty.worktree_snapshot.state, "dirty");
    assert.equal(dirty.worktree_snapshot.untracked_file_count, 1);
    assert.notEqual(dirty.worktree_snapshot.sha256, clean.worktree_snapshot.sha256);
    assert.notEqual(
      dirty.worktree_snapshot.tracked_diff_sha256,
      clean.worktree_snapshot.tracked_diff_sha256,
    );
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});
