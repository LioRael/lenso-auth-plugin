/** Private event-owned Auth bridge. Do not cache closures or their promises. */
function createD1Binding(database, lifecycle) {
  if (!database || typeof database.prepare !== 'function' || typeof database.batch !== 'function') {
    throw new Error('Auth requires its configured D1 database binding');
  }
  return function batch(input) {
    if (lifecycle.isClosed()) return Promise.reject(new Error('Auth storage event is closed'));
    const statements = JSON.parse(input);
    // No Sessions API: every authentication read must use the primary database.
    const prepared = statements.map(({sql, params}) => database.prepare(sql).bind(...params));
    const pending = database.batch(prepared);
    return lifecycle.forward(pending);
  };
}
/** D1 cannot abort queries. Bound cleanup and silence callbacks before Wasm reset. */
export function createD1StorageScope({cleanupTimeoutMs = 250} = {}) {
  let closed = false;
  const pending = new Set();
  const gates = new Set();
  const lifecycle = {
    isClosed: () => closed,
    forward(nativePromise) {
      const gate = {};
      const forwarded = new Promise((resolve, reject) => { gate.resolve = resolve; gate.reject = reject; });
      gates.add(gate); pending.add(nativePromise);
      // These handlers touch only JS data after invalidation; no old Wasm callbacks.
      nativePromise.then(results => {
        pending.delete(nativePromise); gates.delete(gate);
        if (gate.resolve) {
          try { gate.resolve(JSON.stringify(results)); } catch (error) { gate.reject?.(error); }
        }
        gate.resolve = gate.reject = undefined;
      }, error => {
        pending.delete(nativePromise); gates.delete(gate);
        gate.reject?.(error); gate.resolve = gate.reject = undefined;
      });
      return forwarded;
    },
  };
  const invalidate = () => {
    closed = true;
    for (const gate of gates) gate.resolve = gate.reject = undefined;
    gates.clear();
  };
  return {
    bind(database) { return createD1Binding(database, lifecycle); },
    close() { closed = true; },
    // Never invokes native I/O or a Rust closure. Runner calls before generation reset.
    invalidate,
    async settled() {
      if (!pending.size) return true;
      let timer;
      try {
        const clean = await Promise.race([
          Promise.allSettled([...pending]).then(() => true),
          new Promise(resolve => { timer = setTimeout(() => resolve(false), cleanupTimeoutMs); }),
        ]);
        if (!clean) invalidate();
        return clean;
      } finally { clearTimeout(timer); }
    },
  };
}
