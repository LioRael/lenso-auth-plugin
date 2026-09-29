import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import test from "node:test";
import { bindActor } from "./actor.ts";

const seed = createHash("sha256").update("shared-auth-key").digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
const now = new Date("2027-01-15T08:00:00Z");
const assertion = {
  actor_kind: "user", assurance: "password", audience: ["management@1:read"],
  claims: { a: "first", z: "last" }, expires_at: "2027-01-15T08:01:00Z", issued_at: "2027-01-15T07:59:59Z",
  issuer: "operators", parent_provenance: null, subject: "same-subject",
};
const proof = sign(null, Buffer.from(JSON.stringify(assertion)), privateKey).toString("base64url");
const wire = { ...assertion, proof };
const extension = { key: "lenso.auth.actor-assertion", value: Array.from(Buffer.from(JSON.stringify(wire))), issuer: "operators", audience: wire.audience, proof, sealed: true };

test("Ed25519 verification uses public authority and exact operation admission", async () => {
  assert.equal((await bindActor([extension], "management@1", "read", "operators", publicKey, "user", now)).subject, "same-subject");
  await assert.rejects(bindActor([extension], "management@1", "write", "operators", publicKey, "user", now));
  await assert.rejects(bindActor([extension], "management@1", "read", "app", publicKey, "user", now));
  await assert.rejects(bindActor([extension], "management@1", "read", "operators", publicKey, "service-account", now));
  await assert.rejects(bindActor([extension], "management@1", "read", "operators", publicKey, "user", new Date(wire.expires_at)));
  await assert.rejects(bindActor([extension, extension], "management@1", "read", "operators", publicKey, "user", now));
});

test("claim ordering matches Rust BTreeMap signing and tampering is rejected", async () => {
  const reordered = { ...wire, claims: { z: "last", a: "first" } };
  const reorderedExtension = { ...extension, value: Array.from(Buffer.from(JSON.stringify(reordered))) };
  assert.equal((await bindActor([reorderedExtension], "management@1", "read", "operators", publicKey, "user", now)).subject, "same-subject");
  const tampered = { ...wire, subject: "attacker" };
  await assert.rejects(bindActor([{ ...extension, value: Array.from(Buffer.from(JSON.stringify(tampered))) }], "management@1", "read", "operators", publicKey, "user", now));
  await assert.rejects(bindActor([extension], "management@1", "read", "operators", `${publicKey}=`, "user", now));
});
