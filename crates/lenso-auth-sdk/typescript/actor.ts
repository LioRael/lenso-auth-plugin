export type WireExtension = {
  key: string;
  value: number[];
  issuer?: string;
  audience?: string[];
  proof?: string;
  sealed?: boolean;
};

export type ActorAssertion = {
  actor_kind: string;
  assurance: string;
  audience: string[];
  claims?: Record<string, unknown>;
  expires_at: string;
  issued_at: string;
  issuer: string;
  parent_provenance?: string;
  proof: string;
  subject: string;
};

export class ActorBindingError extends Error {}

const decodeBase64Url = (value: string, size: number): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new ActorBindingError("invalid base64url authority");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== size || bytes.toString("base64url") !== value) throw new ActorBindingError("invalid base64url authority");
  return bytes;
};

const canonicalClaims = (value: unknown): unknown => {
  if (typeof value === "number" && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) throw new ActorBindingError("nonportable assertion claim");
  if (Array.isArray(value)) return value.map(canonicalClaims);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, entry]) => [key, canonicalClaims(entry)]));
  return value;
};

export async function bindActor(
  extensions: WireExtension[] | undefined,
  capabilityId: string,
  operation: string,
  expectedIssuer: string,
  verificationKey: string,
  actorKind: string,
  now = new Date(),
): Promise<ActorAssertion> {
  const expectedAudience = `${capabilityId}:${operation}`;
  const matching = extensions?.filter((candidate) => candidate.key === "lenso.auth.actor-assertion") ?? [];
  const extension = matching.length === 1 ? matching[0] : undefined;
  if (
    !extension?.sealed ||
    !Array.isArray(extension.value) ||
    !extension.value.every((value) => Number.isInteger(value) && value >= 0 && value <= 255) ||
    extension.issuer !== expectedIssuer ||
    !extension.audience?.includes(expectedAudience) ||
    !extension.proof ||
    extension.value.length === 0
  ) {
    throw new ActorBindingError("actor assertion is missing or not target-bound");
  }

  let assertion: ActorAssertion;
  try {
    assertion = JSON.parse(
      new TextDecoder().decode(new Uint8Array(extension.value)),
    ) as ActorAssertion;
  } catch {
    throw new ActorBindingError("actor assertion is not valid JSON");
  }
  if (
    !assertion ||
    typeof assertion !== "object" ||
    assertion.actor_kind !== actorKind ||
    typeof assertion.assurance !== "string" ||
    assertion.assurance.length === 0 ||
    !Array.isArray(assertion.audience) ||
    !assertion.audience.every((entry) => typeof entry === "string") ||
    !assertion.audience.includes(expectedAudience) ||
    JSON.stringify(assertion.audience) !== JSON.stringify(extension.audience) ||
    assertion.issuer !== expectedIssuer ||
    typeof assertion.subject !== "string" ||
    assertion.subject.length === 0 ||
    typeof assertion.proof !== "string" ||
    assertion.proof !== extension.proof ||
    typeof assertion.issued_at !== "string" ||
    typeof assertion.expires_at !== "string"
  ) {
    throw new ActorBindingError("actor assertion shape is invalid");
  }
  const issuedAt = Date.parse(assertion.issued_at);
  const expiresAt = Date.parse(assertion.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt >= expiresAt) {
    throw new ActorBindingError("actor assertion validity is invalid");
  }
  if (!Number.isFinite(now.getTime()) || now.getTime() < issuedAt || now.getTime() >= expiresAt) {
    throw new ActorBindingError("actor assertion is outside its validity interval");
  }

  const signingPayload = JSON.stringify({
    actor_kind: assertion.actor_kind,
    assurance: assertion.assurance,
    audience: assertion.audience,
    claims: canonicalClaims(assertion.claims ?? null),
    expires_at: assertion.expires_at,
    issued_at: assertion.issued_at,
    issuer: assertion.issuer,
    parent_provenance: assertion.parent_provenance ?? null,
    subject: assertion.subject,
  });
  let key: CryptoKey;
  let proof: Uint8Array;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      decodeBase64Url(verificationKey, 32),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    proof = decodeBase64Url(assertion.proof, 64);
  } catch {
    throw new ActorBindingError("actor assertion verification authority is invalid");
  }
  if (!(await crypto.subtle.verify("Ed25519", key, proof, new TextEncoder().encode(signingPayload)))) {
    throw new ActorBindingError("actor assertion proof is invalid");
  }
  return assertion;
}
