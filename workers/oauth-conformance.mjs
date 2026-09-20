// Machine-readable, scenario-oriented evidence for the OAuth consume-once
// invariant. This runner intentionally distinguishes a local candidate from
// an actual infrastructure qualification. In particular, a local workerd
// callback cohort is not evidence of D1, Hyperdrive, or PostgreSQL.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_PATH = fileURLToPath(import.meta.url);
const WORKERS_DIRECTORY = dirname(MODULE_PATH);
const REPOSITORY_ROOT = resolve(WORKERS_DIRECTORY, "..");
const DEFAULT_MATRIX_PATH = resolve(WORKERS_DIRECTORY, "oauth-conformance.matrix.json");
const MATRIX_SCHEMA = "lenso.auth.oauth-flow-conformance-matrix@1";
const RECEIPT_SCHEMA = "lenso.auth.oauth-flow-conformance-receipt@1";
const TARGET_RECEIPT_SCHEMA = "lenso.auth.oauth-flow-target-receipt@1";
const BUSINESS_STATUSES = new Set(["passed", "failed", "not-run"]);
const QUALIFICATION_LEVELS = new Set(["local", "target", "not-run"]);
const QUALIFICATION_STATUSES = new Set(["passed", "failed", "pending"]);

function fail(message) {
  throw new Error(`OAuth conformance: ${message}`);
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertObject(value, label) {
  if (!isObject(value)) fail(`${label} must be an object`);
}

function assertString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
}

function assertStringArray(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    fail(`${label} must be an array of non-empty strings`);
  }
  if (new Set(value).size !== value.length) fail(`${label} must not contain duplicates`);
}

function sameMembers(actual, expected) {
  return actual.length === expected.length && actual.every((item) => expected.includes(item));
}

function updateFramed(hash, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  hash.update(String(bytes.length));
  hash.update("\0");
  hash.update(bytes);
  hash.update("\0");
}

/**
 * Captures the source actually exercised by a local candidate. `base_revision`
 * alone is intentionally insufficient: the tracked diff and every untracked
 * source file participate in the snapshot digest.
 */
export function captureWorktreeSnapshot(repositoryRoot = REPOSITORY_ROOT) {
  const runGit = (args, options = {}) => {
    try {
      return execFileSync("git", args, {
        cwd: repositoryRoot,
        maxBuffer: 32 * 1024 * 1024,
        ...options,
      });
    } catch (error) {
      fail(`git ${args.join(" ")} failed: ${error.message}`);
    }
  };
  const baseRevision = String(runGit(["rev-parse", "HEAD"], { encoding: "utf8" })).trim();
  if (!/^[0-9a-f]{40}$/i.test(baseRevision)) {
    fail(`git HEAD is not a full commit SHA: ${baseRevision}`);
  }
  const trackedDiff = Buffer.from(runGit(["diff", "--binary", "HEAD"], { encoding: "buffer" }));
  const untrackedOutput = Buffer.from(
    runGit(["ls-files", "--others", "--exclude-standard", "-z"], { encoding: "buffer" }),
  );
  const untrackedPaths = untrackedOutput
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .sort();
  const untrackedHasher = createHash("sha256");
  for (const relativePath of untrackedPaths) {
    const absolutePath = resolve(repositoryRoot, relativePath);
    const metadata = lstatSync(absolutePath);
    updateFramed(untrackedHasher, relativePath);
    updateFramed(untrackedHasher, String(metadata.mode));
    if (metadata.isSymbolicLink()) {
      // Git tracks link targets, not the content of their destination.
      updateFramed(untrackedHasher, "symbolic-link");
      updateFramed(untrackedHasher, readlinkSync(absolutePath));
    } else if (metadata.isFile()) {
      updateFramed(untrackedHasher, "file");
      updateFramed(untrackedHasher, readFileSync(absolutePath));
    } else {
      fail(`untracked path ${relativePath} is neither a file nor a symbolic link`);
    }
  }
  const trackedDiffSha256 = sha256(trackedDiff);
  const untrackedContentSha256 = `sha256:${untrackedHasher.digest("hex")}`;
  const snapshotHasher = createHash("sha256");
  updateFramed(snapshotHasher, "lenso.git-worktree-snapshot@1");
  updateFramed(snapshotHasher, baseRevision);
  updateFramed(snapshotHasher, trackedDiff);
  updateFramed(snapshotHasher, Buffer.from(untrackedContentSha256));
  const dirty = trackedDiff.length > 0 || untrackedPaths.length > 0;
  return {
    base_revision: baseRevision,
    worktree_snapshot: {
      schema: "lenso.git-worktree-snapshot@1",
      state: dirty ? "dirty" : "clean",
      sha256: `sha256:${snapshotHasher.digest("hex")}`,
      tracked_diff_sha256: trackedDiffSha256,
      untracked_file_count: untrackedPaths.length,
      untracked_content_sha256: untrackedContentSha256,
    },
  };
}

export function validateMatrix(matrix) {
  assertObject(matrix, "matrix");
  if (matrix.schema !== MATRIX_SCHEMA) fail(`matrix.schema must be ${MATRIX_SCHEMA}`);
  assertObject(matrix.scenario, "matrix.scenario");
  assertString(matrix.scenario.id, "matrix.scenario.id");
  if (!Array.isArray(matrix.scenario.business_invariants) || matrix.scenario.business_invariants.length === 0) {
    fail("matrix.scenario.business_invariants must be a non-empty array");
  }
  const invariantIds = matrix.scenario.business_invariants.map((invariant, index) => {
    assertObject(invariant, `matrix.scenario.business_invariants[${index}]`);
    assertString(invariant.id, `matrix.scenario.business_invariants[${index}].id`);
    assertString(invariant.assertion, `matrix.scenario.business_invariants[${index}].assertion`);
    return invariant.id;
  });
  if (new Set(invariantIds).size !== invariantIds.length) {
    fail("matrix.scenario.business_invariants must not repeat ids");
  }
  if (!Array.isArray(matrix.compositions) || matrix.compositions.length !== 4) {
    fail("matrix.compositions must contain the four declared compositions");
  }
  const compositionIds = matrix.compositions.map((composition, index) => {
    assertObject(composition, `matrix.compositions[${index}]`);
    assertString(composition.id, `matrix.compositions[${index}].id`);
    assertString(composition.environment, `matrix.compositions[${index}].environment`);
    assertString(composition.infrastructure, `matrix.compositions[${index}].infrastructure`);
    assertStringArray(
      composition.business_invariant_ids,
      `matrix.compositions[${index}].business_invariant_ids`,
    );
    if (!sameMembers(composition.business_invariant_ids, invariantIds)) {
      fail(`${composition.id} must cover every common business invariant exactly once`);
    }
    if (!["local", "target"].includes(composition.required_qualification_level)) {
      fail(`${composition.id}.required_qualification_level must be local or target`);
    }
    assertStringArray(
      composition.qualification_requirements,
      `${composition.id}.qualification_requirements`,
    );
    if (composition.local_command !== undefined) validateLocalCommand(composition.local_command, composition.id);
    return composition.id;
  });
  if (new Set(compositionIds).size !== compositionIds.length) {
    fail("matrix.compositions must not repeat ids");
  }
  const expectedCompositions = [
    "simulated-deterministic-store",
    "native-postgresql",
    "workers-d1",
    "workers-hyperdrive-postgresql",
  ];
  if (!sameMembers(compositionIds, expectedCompositions)) {
    fail(`matrix.compositions must be ${expectedCompositions.join(", ")}`);
  }
  return matrix;
}

function validateLocalCommand(command, compositionId) {
  assertObject(command, `${compositionId}.local_command`);
  assertString(command.id, `${compositionId}.local_command.id`);
  assertString(command.program, `${compositionId}.local_command.program`);
  assertStringArray(command.args, `${compositionId}.local_command.args`);
  if (command.requires_environment !== undefined) {
    assertString(command.requires_environment, `${compositionId}.local_command.requires_environment`);
  }
  if (command.receipt_prefix !== undefined) {
    assertString(command.receipt_prefix, `${compositionId}.local_command.receipt_prefix`);
  }
}

export function loadMatrix(matrixPath = DEFAULT_MATRIX_PATH) {
  const resolvedPath = matrixPath instanceof URL ? fileURLToPath(matrixPath) : resolve(matrixPath);
  const source = readFileSync(resolvedPath);
  const matrix = validateMatrix(JSON.parse(source.toString("utf8")));
  return { matrix, digest: sha256(source), path: resolvedPath };
}

function requirementStatusMaps(run, composition) {
  assertObject(run.qualification, `${composition.id}.qualification`);
  const { level, status, satisfied_requirement_ids: satisfied, pending_requirement_ids: pending } = run.qualification;
  if (!QUALIFICATION_LEVELS.has(level)) fail(`${composition.id}.qualification.level is invalid`);
  if (!QUALIFICATION_STATUSES.has(status)) fail(`${composition.id}.qualification.status is invalid`);
  assertStringArray(satisfied, `${composition.id}.qualification.satisfied_requirement_ids`);
  assertStringArray(pending, `${composition.id}.qualification.pending_requirement_ids`);
  if (satisfied.some((requirement) => pending.includes(requirement))) {
    fail(`${composition.id}.qualification requirements cannot be both satisfied and pending`);
  }
  const combined = [...satisfied, ...pending];
  if (!sameMembers(combined, composition.qualification_requirements)) {
    fail(`${composition.id}.qualification must classify every declared qualification requirement`);
  }
  return { level, status, satisfied, pending };
}

function validateEvidence(evidence, composition) {
  if (!Array.isArray(evidence)) fail(`${composition.id}.evidence must be an array`);
  for (const [index, item] of evidence.entries()) {
    assertObject(item, `${composition.id}.evidence[${index}]`);
    assertString(item.kind, `${composition.id}.evidence[${index}].kind`);
    if (!["local", "actual-target"].includes(item.scope)) {
      fail(`${composition.id}.evidence[${index}].scope must be local or actual-target`);
    }
    assertString(item.reference, `${composition.id}.evidence[${index}].reference`);
  }
}

function businessStatus(run, composition) {
  assertObject(run.business_invariants, `${composition.id}.business_invariants`);
  const keys = Object.keys(run.business_invariants).sort();
  const expected = [...composition.business_invariant_ids].sort();
  if (!sameMembers(keys, expected)) {
    fail(`${composition.id}.business_invariants must contain every common invariant exactly once`);
  }
  for (const [invariant, status] of Object.entries(run.business_invariants)) {
    if (!BUSINESS_STATUSES.has(status)) {
      fail(`${composition.id}.business_invariants.${invariant} is invalid`);
    }
  }
  return Object.values(run.business_invariants);
}

function allBusinessPassed(run) {
  return Object.values(run.business_invariants).every((status) => status === "passed");
}

function allBusinessNotRun(run) {
  return Object.values(run.business_invariants).every((status) => status === "not-run");
}

function hasActualTargetEvidence(evidence) {
  return evidence.some((item) => item.scope === "actual-target");
}

/**
 * Validates a receipt's shape and provenance rules. It does not upgrade a
 * local receipt: callers must pass `requireQualified` to use it as a gate.
 */
export function validateReceipt(loadedMatrix, receipt) {
  const { matrix, digest } = loadedMatrix;
  validateMatrix(matrix);
  assertObject(receipt, "receipt");
  if (receipt.schema !== RECEIPT_SCHEMA) fail(`receipt.schema must be ${RECEIPT_SCHEMA}`);
  if (receipt.matrix_schema !== matrix.schema) fail("receipt.matrix_schema does not match matrix.schema");
  if (receipt.matrix_digest !== digest) fail("receipt.matrix_digest does not match the matrix bytes used for validation");
  if (receipt.scenario_id !== matrix.scenario.id) fail("receipt.scenario_id does not match matrix.scenario.id");
  assertObject(receipt.source, "receipt.source");
  assertString(receipt.source.base_revision, "receipt.source.base_revision");
  if (!/^[0-9a-f]{40}$/i.test(receipt.source.base_revision)) {
    fail("receipt.source.base_revision must be a full commit SHA");
  }
  assertObject(receipt.source.worktree_snapshot, "receipt.source.worktree_snapshot");
  const snapshot = receipt.source.worktree_snapshot;
  if (snapshot.schema !== "lenso.git-worktree-snapshot@1") {
    fail("receipt.source.worktree_snapshot.schema is invalid");
  }
  if (!["clean", "dirty"].includes(snapshot.state)) {
    fail("receipt.source.worktree_snapshot.state must be clean or dirty");
  }
  for (const key of ["sha256", "tracked_diff_sha256", "untracked_content_sha256"]) {
    assertString(snapshot[key], `receipt.source.worktree_snapshot.${key}`);
    if (!/^sha256:[0-9a-f]{64}$/i.test(snapshot[key])) {
      fail(`receipt.source.worktree_snapshot.${key} must be a SHA-256 digest`);
    }
  }
  if (!Number.isInteger(snapshot.untracked_file_count) || snapshot.untracked_file_count < 0) {
    fail("receipt.source.worktree_snapshot.untracked_file_count must be a non-negative integer");
  }
  if (!Array.isArray(receipt.runs)) fail("receipt.runs must be an array");
  const expectedIds = matrix.compositions.map((composition) => composition.id);
  if (receipt.runs.length !== expectedIds.length) fail("receipt.runs must have one run for each composition");
  const seen = new Set();
  for (const run of receipt.runs) {
    assertObject(run, "receipt.runs entry");
    assertString(run.composition_id, "receipt.runs[].composition_id");
    if (seen.has(run.composition_id)) fail(`receipt.runs repeats ${run.composition_id}`);
    seen.add(run.composition_id);
    const composition = matrix.compositions.find((entry) => entry.id === run.composition_id);
    if (!composition) fail(`receipt.runs includes unknown composition ${run.composition_id}`);
    businessStatus(run, composition);
    const qualification = requirementStatusMaps(run, composition);
    validateEvidence(run.evidence, composition);

    if (qualification.level === "not-run") {
      if (qualification.status !== "pending" || qualification.satisfied.length !== 0 || !allBusinessNotRun(run)) {
        fail(`${composition.id} not-run receipts must leave business and qualification requirements pending`);
      }
      if (run.evidence.length !== 0) fail(`${composition.id} not-run receipts must not include evidence`);
      continue;
    }
    if (qualification.status === "passed" && !allBusinessPassed(run)) {
      fail(`${composition.id} passed qualification requires all business invariants to pass`);
    }
    if (qualification.level === "target") {
      if (composition.required_qualification_level !== "target") {
        fail(`${composition.id} may not claim target qualification when the matrix only requires local qualification`);
      }
      if (qualification.status !== "passed") {
        fail(`${composition.id} target qualification must be passed, not pending or failed`);
      }
      if (qualification.pending.length !== 0 || qualification.satisfied.length !== composition.qualification_requirements.length) {
        fail(`${composition.id} target qualification must satisfy every declared requirement`);
      }
      if (!hasActualTargetEvidence(run.evidence)) {
        fail(`${composition.id} target qualification requires actual target evidence`);
      }
      if (snapshot.state !== "clean") {
        fail(`${composition.id} target qualification cannot be claimed from a dirty worktree snapshot`);
      }
    } else if (qualification.level === "local") {
      if (composition.required_qualification_level === "local" && qualification.status === "passed") {
        if (qualification.pending.length !== 0) {
          fail(`${composition.id} local qualification must satisfy every local requirement`);
        }
      }
      if (composition.required_qualification_level === "target" && qualification.status === "passed") {
        if (qualification.satisfied.length !== 0) {
          fail(`${composition.id} local candidate may not mark target requirements satisfied`);
        }
      }
      if (!run.evidence.some((item) => item.scope === "local")) {
        fail(`${composition.id} local qualification must include local evidence`);
      }
    }
  }
  if (!sameMembers([...seen], expectedIds)) fail("receipt.runs does not cover every matrix composition");
  assertObject(receipt.summary, "receipt.summary");
  const expectedSummary = summarizeReceipt(receipt);
  if (receipt.summary.business_conformance !== expectedSummary.business_conformance) {
    fail("receipt.summary.business_conformance is inconsistent with receipt.runs");
  }
  if (receipt.summary.qualification !== expectedSummary.qualification) {
    fail("receipt.summary.qualification is inconsistent with receipt.runs");
  }
  return receipt;
}

export function summarizeReceipt(receipt) {
  const businessStatuses = receipt.runs.flatMap((run) => Object.values(run.business_invariants));
  const businessConformance = businessStatuses.includes("failed")
    ? "failed"
    : businessStatuses.length > 0 && businessStatuses.every((status) => status === "passed")
      ? "passed"
      : "incomplete";
  const qualificationStatuses = receipt.runs.map((run) => run.qualification.status);
  const allTargetOrLocalPassed = receipt.runs.every(
    (run) => run.qualification.status === "passed" && run.qualification.level !== "not-run",
  );
  const requiredTargetRuns = receipt.runs.filter((run) => run.composition_id !== "simulated-deterministic-store");
  const targetsPassed = requiredTargetRuns.every(
    (run) => run.qualification.level === "target" && run.qualification.status === "passed",
  );
  const qualification = qualificationStatuses.includes("failed")
    ? "failed"
    : allTargetOrLocalPassed && targetsPassed
      ? "passed"
      : "incomplete";
  return { business_conformance: businessConformance, qualification };
}

export function requireQualified(receipt) {
  if (receipt.summary.business_conformance !== "passed") {
    fail(`business conformance is ${receipt.summary.business_conformance}, not passed`);
  }
  if (receipt.summary.qualification !== "passed") {
    fail(`qualification is ${receipt.summary.qualification}, not passed`);
  }
}

/**
 * A structurally valid receipt can describe a different checkout. Gates must
 * bind it to the source they are about to accept, rather than trusting only a
 * historical base SHA in the JSON file.
 */
export function requireCurrentSource(receipt, currentSource = captureWorktreeSnapshot()) {
  if (stableJson(receipt.source) !== stableJson(currentSource)) {
    fail("receipt source snapshot does not match the current worktree");
  }
}

function emptyBusinessInvariants(composition, status) {
  return Object.fromEntries(composition.business_invariant_ids.map((invariant) => [invariant, status]));
}

function noRun(composition, note) {
  return {
    composition_id: composition.id,
    business_invariants: emptyBusinessInvariants(composition, "not-run"),
    qualification: {
      level: "not-run",
      status: "pending",
      satisfied_requirement_ids: [],
      pending_requirement_ids: [...composition.qualification_requirements],
    },
    evidence: [],
    note,
  };
}

function outputEvidence(command, run) {
  return {
    kind: "command",
    scope: "local",
    reference: command.id,
    exit_code: run.status ?? (run.error ? 1 : 0),
    output_sha256: sha256(Buffer.from(`${run.stdout ?? ""}${run.stderr ?? ""}`)),
  };
}

function runCommand(command) {
  const program = command.program === "cargo" && process.env.LENSO_CARGO
    ? process.env.LENSO_CARGO
    : command.program;
  return spawnSync(program, command.args, {
    cwd: REPOSITORY_ROOT,
    encoding: "utf8",
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
  });
}

function parsedCohortEvidence(command, run) {
  if (!command.receipt_prefix) return undefined;
  const combined = `${run.stdout ?? ""}${run.stderr ?? ""}`;
  const line = combined.split("\n").find((entry) => entry.startsWith(command.receipt_prefix));
  if (!line) return undefined;
  try {
    return JSON.parse(line.slice(command.receipt_prefix.length));
  } catch {
    return undefined;
  }
}

function localRun(composition, command) {
  const run = runCommand(command);
  const evidence = outputEvidence(command, run);
  const cohortEvidence = parsedCohortEvidence(command, run);
  const passed = run.status === 0 && !run.error && (!command.receipt_prefix || cohortEvidence?.passed === true);
  if (!passed) {
    return {
      composition_id: composition.id,
      business_invariants: emptyBusinessInvariants(composition, "not-run"),
      qualification: {
        level: "local",
        status: "failed",
        satisfied_requirement_ids: [],
        pending_requirement_ids: [...composition.qualification_requirements],
      },
      evidence: [evidence],
      note: `Local command ${command.id} did not produce passing scenario evidence.`,
    };
  }
  const targetOnly = composition.required_qualification_level === "target";
  return {
    composition_id: composition.id,
    business_invariants: emptyBusinessInvariants(composition, "passed"),
    qualification: {
      level: "local",
      status: "passed",
      satisfied_requirement_ids: targetOnly ? [] : [...composition.qualification_requirements],
      pending_requirement_ids: targetOnly ? [...composition.qualification_requirements] : [],
    },
    evidence: [evidence],
    note: targetOnly
      ? `Passing ${command.id} is local composition evidence only; it does not qualify ${composition.infrastructure}.`
      : `Passing ${command.id} covers the simulator requirements declared in the matrix.`,
  };
}

function validateTargetReceipt(targetReceipt, composition, source, scenarioId) {
  assertObject(targetReceipt, `${composition.id} target receipt`);
  if (targetReceipt.schema !== TARGET_RECEIPT_SCHEMA) {
    fail(`${composition.id} target receipt.schema must be ${TARGET_RECEIPT_SCHEMA}`);
  }
  if (targetReceipt.composition_id !== composition.id) fail("target receipt composition_id does not match");
  if (targetReceipt.scenario_id !== scenarioId) fail("target receipt scenario_id does not match");
  assertObject(targetReceipt.source, "target receipt.source");
  if (targetReceipt.source.base_revision !== source.base_revision) {
    fail(`${composition.id} target receipt source base_revision does not match this candidate`);
  }
  if (targetReceipt.source.worktree_state !== "clean") {
    fail(`${composition.id} target receipt must be for a clean worktree candidate`);
  }
  assertObject(targetReceipt.business_invariants, "target receipt.business_invariants");
  for (const invariant of composition.business_invariant_ids) {
    if (targetReceipt.business_invariants[invariant] !== "passed") {
      fail(`${composition.id} target receipt must pass ${invariant}`);
    }
  }
  assertObject(targetReceipt.qualification_requirements, "target receipt.qualification_requirements");
  for (const requirement of composition.qualification_requirements) {
    if (targetReceipt.qualification_requirements[requirement] !== "passed") {
      fail(`${composition.id} target receipt must pass ${requirement}`);
    }
  }
  assertObject(targetReceipt.evidence, "target receipt.evidence");
  if (targetReceipt.evidence.scope !== "actual-target") {
    fail(`${composition.id} target receipt evidence.scope must be actual-target`);
  }
  assertString(targetReceipt.evidence.reference, "target receipt.evidence.reference");
  return targetReceipt;
}

function targetRun(composition, targetReceipt, source, scenarioId) {
  validateTargetReceipt(targetReceipt, composition, source, scenarioId);
  return {
    composition_id: composition.id,
    business_invariants: emptyBusinessInvariants(composition, "passed"),
    qualification: {
      level: "target",
      status: "passed",
      satisfied_requirement_ids: [...composition.qualification_requirements],
      pending_requirement_ids: [],
    },
    evidence: [
      {
        kind: "target-receipt",
        scope: "actual-target",
        reference: targetReceipt.evidence.reference,
        receipt_sha256: sha256(Buffer.from(stableJson(targetReceipt))),
      },
    ],
    note: "Operator-provided actual-target receipt matched this clean candidate base revision.",
  };
}

function parseCliArguments(argv) {
  const [command, ...rest] = argv;
  const options = { command, targetReceipts: new Map() };
  for (let index = 0; index < rest.length; index += 1) {
    const option = rest[index];
    if (option === "--matrix" || option === "--receipt" || option === "--output") {
      const value = rest[++index];
      if (!value) fail(`${option} requires a path`);
      options[option.slice(2)] = resolve(value);
    } else if (
      option === "--native-postgres" ||
      option === "--require-qualified" ||
      option === "--require-current-source"
    ) {
      options[option.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = true;
    } else if (option === "--target-receipt") {
      const compositionId = rest[++index];
      const receiptPath = rest[++index];
      if (!compositionId || !receiptPath) fail("--target-receipt requires a composition id and path");
      if (options.targetReceipts.has(compositionId)) fail(`target receipt repeated for ${compositionId}`);
      options.targetReceipts.set(compositionId, resolve(receiptPath));
    } else {
      fail(`unknown option ${option}`);
    }
  }
  return options;
}

export function runLocal(loadedMatrix, options = {}) {
  const { matrix, digest } = loadedMatrix;
  const source = captureWorktreeSnapshot();
  const targetReceipts = options.targetReceipts ?? new Map();
  for (const compositionId of targetReceipts.keys()) {
    if (!matrix.compositions.some((composition) => composition.id === compositionId)) {
      fail(`target receipt names unknown composition ${compositionId}`);
    }
  }
  if (targetReceipts.size > 0 && source.worktree_snapshot.state !== "clean") {
    fail("actual-target receipts cannot be attached to a dirty worktree snapshot");
  }
  const runs = matrix.compositions.map((composition) => {
    const targetReceiptPath = targetReceipts.get(composition.id);
    if (targetReceiptPath) {
      const targetReceipt = JSON.parse(readFileSync(targetReceiptPath, "utf8"));
      return targetRun(composition, targetReceipt, source, matrix.scenario.id);
    }
    if (!composition.local_command) {
      return noRun(composition, "No local command is declared; an actual-target receipt is required.");
    }
    const command = composition.local_command;
    if (command.requires_environment && !options.nativePostgres) {
      return noRun(
        composition,
        `${command.id} is opt-in; pass --native-postgres after selecting a disposable target.`,
      );
    }
    if (command.requires_environment && !process.env[command.requires_environment]) {
      return noRun(
        composition,
        `${command.id} requires ${command.requires_environment}; no command was run.`,
      );
    }
    return localRun(composition, command);
  });
  const sourceAfterRuns = captureWorktreeSnapshot();
  if (stableJson(sourceAfterRuns) !== stableJson(source)) {
    fail("worktree snapshot changed while conformance commands ran; no receipt was emitted");
  }
  const receipt = {
    schema: RECEIPT_SCHEMA,
    matrix_schema: matrix.schema,
    matrix_digest: digest,
    scenario_id: matrix.scenario.id,
    source,
    runs,
  };
  receipt.summary = summarizeReceipt(receipt);
  return validateReceipt(loadedMatrix, receipt);
}

function usage() {
  return [
    "Usage:",
    "  node workers/oauth-conformance.mjs run-local --output <receipt.json> [--matrix <matrix.json>] [--native-postgres] [--target-receipt <composition-id> <receipt.json>]...",
    "  node workers/oauth-conformance.mjs validate --receipt <receipt.json> [--matrix <matrix.json>] [--require-current-source] [--require-qualified]",
  ].join("\n");
}

async function main() {
  const options = parseCliArguments(process.argv.slice(2));
  if (!options.command || options.command === "--help" || options.command === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const loadedMatrix = loadMatrix(options.matrix);
  if (options.command === "run-local") {
    if (!options.output) fail("run-local requires --output");
    const receipt = runLocal(loadedMatrix, options);
    writeFileSync(options.output, `${JSON.stringify(receipt, null, 2)}\n`);
    process.stdout.write(
      `OAuth conformance receipt: ${options.output} (business=${receipt.summary.business_conformance}, qualification=${receipt.summary.qualification})\n`,
    );
    if (options.requireQualified) requireQualified(receipt);
    return;
  }
  if (options.command === "validate") {
    if (!options.receipt) fail("validate requires --receipt");
    const receipt = validateReceipt(loadedMatrix, JSON.parse(readFileSync(options.receipt, "utf8")));
    if (options.requireCurrentSource || options.requireQualified) requireCurrentSource(receipt);
    if (options.requireQualified) requireQualified(receipt);
    process.stdout.write(
      `OAuth conformance receipt is valid (business=${receipt.summary.business_conformance}, qualification=${receipt.summary.qualification})\n`,
    );
    return;
  }
  fail(`unknown command ${options.command}\n${usage()}`);
}

if (process.argv[1] && resolve(process.argv[1]) === MODULE_PATH) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
