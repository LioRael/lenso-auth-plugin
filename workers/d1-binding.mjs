/** Private Auth persistence transport; lifecycle belongs to the Host event scope. */
export function createD1Binding(database, scope) {
  if (!database || typeof database.prepare !== 'function' || typeof database.batch !== 'function') {
    throw new Error('Auth requires its configured D1 database binding');
  }
  if (!scope || typeof scope.run !== 'function') throw new Error('Auth requires an event resource scope');
  return function batch(input) {
    return scope.run(() => {
      const statements = JSON.parse(input);
      if (!Array.isArray(statements) || !statements.length || statements.length > 128) {
        throw new Error('Invalid Auth statement batch');
      }
      // Primary database only. Replica/session reads cannot decide revocation.
      const prepared = statements.map(({ sql, params }) => {
        if (typeof sql !== 'string' || !Array.isArray(params)) throw new Error('Invalid Auth statement');
        return database.prepare(sql).bind(...params);
      });
      return database.batch(prepared);
    }, JSON.stringify);
  };
}
