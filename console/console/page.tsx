import { useWorkspaceRead, useWorkspaceReadClient, type PageProps } from "@lenso/console-sdk";
import { AlertDialog } from "@lenso/ui/alert-dialog";
import { Button } from "@lenso/ui/button";
import { Input } from "@lenso/ui/input";
import { useState } from "react";

type Mutation = "set_subject_status" | "revoke_session";
type Policy = { allowed_mutations: Mutation[]; access_scope: { kind: string; id: string }; title: string };
type Subject = { subject: string; status: "active" | "disabled"; disabled_reason: string | null; disabled_until: string | null; created_at: string };
type Subjects = { subjects: Subject[]; next_cursor: string | null };
type Session = { session_id: string; subject: string; actor_kind: string; assurance: string; expires_at: string; revoked: boolean; created_at: string };
type Sessions = { sessions: Session[]; next_cursor: string | null };
type Pending = { operation: Mutation; input: Record<string, string | null>; description: string };
const fresh = { staleTimeMs: 0, remount: "always", focus: "always", gcTimeMs: 0 } as const;
const tableStyle = { width: "100%", minWidth: 640, tableLayout: "fixed", textAlign: "left", borderSpacing: "0 12px", overflowWrap: "anywhere" } as const;

export default function Accounts({ services, signal, mount }: PageProps) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [subjectDraft, setSubjectDraft] = useState("");
  const [subject, setSubject] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState("");
  const reads = useWorkspaceReadClient();
  const policyRead = useWorkspaceRead({
    key: "auth.account.policy", params: {}, policy: fresh,
    read: ({ signal }) => services.invoke<object, Policy>("account-admin", "read_policy", {}, { signal }),
  });
  const subjectsRead = useWorkspaceRead({
    key: "auth.account.subjects", params: { cursor }, policy: fresh,
    read: ({ params, signal }) => services.invoke<{ limit: number; cursor: string | null }, Subjects>(
      "account-admin", "list_subjects", { limit: 25, cursor: params.cursor }, { signal }),
  });
  const policy = policyRead.error || policyRead.blocking || policyRead.refreshing ? undefined : policyRead.data;
  const page = subjectsRead.error || subjectsRead.blocking || subjectsRead.refreshing ? undefined : subjectsRead.data;
  const enabled = (operation: Mutation) => !busy && !!policy?.allowed_mutations.includes(operation);

  const mutate = async () => {
    const action = pending;
    if (!action || !enabled(action.operation)) return;
    setPending(null);
    setBusy(true);
    setOutcome("");
    try {
      const result = await services.invoke<Record<string, string | boolean | null>, { changed: boolean }>(
        "account-admin", action.operation, { ...action.input, confirmed: true }, { signal });
      if (signal.aborted) return;
      setOutcome(result.changed ? "The Account owner acknowledged the change." : "The Account owner reported no change was needed.");
      try {
        await Promise.all([
          reads.invalidate({ key: "auth.account.subjects" }),
          reads.invalidate({ key: "auth.account.sessions" }),
          reads.invalidate({ key: "auth.account.policy" }),
        ]);
      } catch {
        if (!signal.aborted) setOutcome("The change was acknowledged, but current state could not be refreshed. Read it again before another action.");
      }
    } catch {
      if (!signal.aborted) setOutcome("Could not confirm the change. Read current state before trying again.");
    } finally {
      if (!signal.aborted) setBusy(false);
    }
  };

  return <section aria-label="Accounts and sessions" style={{ padding: 24, maxWidth: 1100, margin: "0 auto" }}>
    <h1>{mount.title}</h1>
    {policy && <p>Access scope: {policy.access_scope.kind} / {policy.access_scope.id}</p>}
    {policyRead.error && <p role="alert">Workspace policy is unavailable. Check your current access.</p>}
    <p>Canonical accounts and session metadata. Credentials are never displayed.</p>
    <div aria-live="polite">{busy && <p>Submitting confirmed change…</p>}{outcome && <p role="status">{outcome}</p>}</div>
    <h2>Accounts</h2>
    {(subjectsRead.blocking || subjectsRead.refreshing) && <p>Reading current accounts…</p>}
    {subjectsRead.error && <p role="alert">Unable to read accounts. Check your access and try again.</p>}
    {page && <>
      {!page.subjects.length ? <p>No accounts found.</p> : <div role="region" aria-label="Account details" tabIndex={0} style={{ overflowX: "auto" }}>
        <table style={tableStyle}><caption style={{ textAlign: "left" }}>Current accounts</caption>
          <thead><tr><th>Subject</th><th>Status</th><th>Details</th><th>Actions</th></tr></thead>
          <tbody>{page.subjects.map((account) => <tr key={account.subject}>
            <td><code>{account.subject}</code></td>
            <td>{account.status}</td>
            <td>{account.disabled_reason ?? "—"}{account.disabled_until && <><br />Until {account.disabled_until}</>}</td>
            <td><div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <Button variant="secondary" size="sm" disabled={busy} onClick={() => { setSubjectDraft(account.subject); setSubject(account.subject); }}>Sessions</Button>
              {policy?.allowed_mutations.includes("set_subject_status") && <Button variant="secondary" size="sm" disabled={!enabled("set_subject_status")}
                onClick={() => setPending({ operation: "set_subject_status", input: { subject: account.subject, status: account.status === "active" ? "disabled" : "active", reason: null, disabled_until: null },
                  description: account.status === "active" ? `Disable ${account.subject}? This revokes all active sessions.` : `Enable ${account.subject}? Previously revoked sessions remain revoked.` })}>
                {account.status === "active" ? "Disable" : "Enable"}
              </Button>}
            </div></td>
          </tr>)}</tbody>
        </table>
      </div>}
    </>}
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 16 }}>
      <Button variant="secondary" disabled={busy || subjectsRead.blocking || subjectsRead.refreshing}
        onClick={() => cursor === null ? void subjectsRead.refetch().catch(() => {}) : setCursor(null)}>Refresh accounts from start</Button>
      <Button variant="secondary" disabled={busy || !page?.next_cursor}
        onClick={() => setCursor(page?.next_cursor ?? null)}>Next account page</Button>
    </div>
    <form style={{ display: "flex", alignItems: "end", gap: 12, flexWrap: "wrap", margin: "32px 0 16px" }}
      onSubmit={(event) => { event.preventDefault(); setSubject(subjectDraft.trim()); }}>
      <label style={{ display: "grid", gap: 8 }}>Subject sessions
        <Input aria-label="Subject sessions" value={subjectDraft} maxLength={256} onChange={(event) => setSubjectDraft(event.target.value)} />
      </label>
      <Button type="submit" disabled={busy || !subjectDraft.trim()}>Read sessions</Button>
    </form>
    {subject && <SessionList key={subject} services={services} subject={subject} busy={busy}
      canRevoke={!!policy?.allowed_mutations.includes("revoke_session")}
      confirm={(session) => setPending({ operation: "revoke_session", input: { session_id: session.session_id }, description: `Revoke session ${session.session_id} for ${session.subject}? This cannot be undone.` })} />}
    <AlertDialog.Root open={pending !== null} onOpenChange={(open) => { if (!open && !busy) setPending(null); }}>
      <AlertDialog.Portal><AlertDialog.Backdrop /><AlertDialog.Viewport><AlertDialog.Popup>
        <AlertDialog.Header><AlertDialog.Title>Confirm Account change</AlertDialog.Title></AlertDialog.Header>
        <AlertDialog.Body><AlertDialog.Description>{pending?.description}</AlertDialog.Description></AlertDialog.Body>
        <AlertDialog.Footer>
          <Button variant="secondary" onClick={() => setPending(null)}>Cancel</Button>
          <Button variant="danger" disabled={!pending || !enabled(pending.operation)} onClick={() => void mutate()}>Confirm change</Button>
        </AlertDialog.Footer>
      </AlertDialog.Popup></AlertDialog.Viewport></AlertDialog.Portal>
    </AlertDialog.Root>
  </section>;
}

function SessionList({ services, subject, busy, canRevoke, confirm }: {
  services: PageProps["services"]; subject: string; busy: boolean; canRevoke: boolean; confirm(session: Session): void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const read = useWorkspaceRead({
    key: "auth.account.sessions", params: { subject, cursor }, policy: fresh,
    read: ({ params, signal }) => services.invoke<{ subject: string; limit: number; cursor: string | null }, Sessions>(
      "account-admin", "list_sessions", { ...params, limit: 25 }, { signal }),
  });
  const loading = read.blocking || read.refreshing;
  const page = read.error || loading ? undefined : read.data;
  return <section aria-label={`Sessions for ${subject}`}>
    <h2>Sessions for {subject}</h2>
    {loading && <p>Reading current sessions…</p>}
    {read.error && <p role="alert">Unable to read sessions. Check your access and try again.</p>}
    {page && (!page.sessions.length ? <p>No sessions found.</p> : <div role="region" aria-label="Session details" tabIndex={0} style={{ overflowX: "auto" }}>
      <table style={tableStyle}><caption style={{ textAlign: "left" }}>Session metadata</caption>
        <thead><tr><th>Session</th><th>Actor and assurance</th><th>Expiry</th><th>Status</th>{canRevoke && <th>Action</th>}</tr></thead>
        <tbody>{page.sessions.map((session) => <tr key={session.session_id}>
          <td><code>{session.session_id}</code></td><td>{session.actor_kind} / {session.assurance}</td><td>{session.expires_at}</td><td>{session.revoked ? "Revoked" : "Not revoked"}</td>
          {canRevoke && <td><Button variant="secondary" size="sm" disabled={busy || session.revoked} onClick={() => confirm(session)}>Revoke</Button></td>}
        </tr>)}</tbody>
      </table>
    </div>)}
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 16 }}>
      <Button variant="secondary" disabled={busy || loading} onClick={() => cursor === null ? void read.refetch().catch(() => {}) : setCursor(null)}>Refresh sessions from start</Button>
      <Button variant="secondary" disabled={busy || !page?.next_cursor} onClick={() => setCursor(page?.next_cursor ?? null)}>Next session page</Button>
    </div>
  </section>;
}
