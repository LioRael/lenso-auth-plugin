/** Proof Host ownership for Web's transport; no Auth or HTTP policy lives here. */
export function createEgressScope({createTransport, fetch, setTimeout, clearTimeout, cleanupTimeoutMs = 250}) {
  let closed = false;
  const pending = new Set(), operations = new Set(), gates = new Set();
  function track(value) {
    const promise = Promise.resolve(value);
    pending.add(promise);
    // Handle both outcomes without creating an unhandled rejected cleanup Promise.
    promise.then(() => pending.delete(promise), () => pending.delete(promise));
    return promise;
  }
  const transport = createTransport({setTimeout, clearTimeout, fetch(...args) {
    if (closed) return Promise.reject({code:'transport_failure'});
    return track(Promise.resolve(fetch(...args)).then(async response => {
      if (closed) {
        // This continuation runs in the native operation's owning event context.
        try { await response.body?.cancel(); } catch { /* Transport is abandoned. */ }
        return response;
      }
      // Web's adapter consumes these Fetch fields. Track native body operations
      // as well as headers: aborting its Promise does not prove a read settled.
      return {status:response.status, headers:response.headers, redirected:response.redirected,
        body:response.body && {getReader() {
          const reader = response.body.getReader();
          return {read:() => track(reader.read()), cancel:() => track(reader.cancel()),
            releaseLock:() => reader.releaseLock()};
        }}};
    }));
  }});
  function invalidate() {
    closed = true;
    for (const gate of gates) gate.resolve = gate.reject = undefined;
    gates.clear();
  }
  return {
    fetch(request) {
      if (closed) return {promise:Promise.reject({code:'transport_failure'}), abort() {}};
      const operation = transport(request), gate = {};
      operations.add(operation);
      const promise = new Promise((resolve, reject) => { gate.resolve = resolve; gate.reject = reject; });
      gates.add(gate);
      track(operation.promise).then(value => {
        operations.delete(operation); gates.delete(gate);
        gate.resolve?.(value); gate.resolve = gate.reject = undefined;
      }, error => {
        operations.delete(operation); gates.delete(gate);
        gate.reject?.(error); gate.resolve = gate.reject = undefined;
      });
      return {promise, abort:() => operation.abort()};
    },
    // Synchronous fencing only: safe before reset, including from a peer event.
    invalidate,
    abort() {
      closed = true;
      // The runner invokes this only in the owning event's finalizer.
      for (const operation of operations) {
        try { operation.abort(); } catch { /* Pending work still bounds cleanup. */ }
      }
    },
    async settled() {
      if (!pending.size) return true;
      let timer;
      try {
        const clean = await Promise.race([
          Promise.allSettled([...pending]).then(() => pending.size === 0),
          new Promise(resolve => { timer = setTimeout(() => resolve(false), cleanupTimeoutMs); }),
        ]);
        if (!clean) invalidate();
        return clean;
      } finally { clearTimeout(timer); }
    },
  };
}
