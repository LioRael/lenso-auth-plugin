// Observations only: the owner's primary batch and returned values are unchanged.
export function observeDatabase(database, counters, { fail = false, memory = () => {} } = {}) {
  return {
    prepare: sql => database.prepare(sql),
    async batch(statements) {
      counters.calls++;
      counters.statements += statements.length;
      memory();
      try {
        if (fail) throw new Error('local D01 injected storage failure');
        const results = await database.batch(statements);
        for (const result of results) {
          counters.returned_rows += result.results?.length ?? 0;
          for (const key of ['rows_read', 'rows_written']) {
            if (typeof result.meta?.[key] === 'number' && counters[key] !== null) counters[key] += result.meta[key];
            else counters[key] = null;
          }
        }
        return results;
      } catch (error) {
        counters.failures++;
        if (!fail) { counters.rows_read = null; counters.rows_written = null; }
        throw error;
      } finally { memory(); }
    },
  };
}
export function counters() {
  return { calls: 0, statements: 0, returned_rows: 0, rows_read: 0, rows_written: 0, failures: 0 };
}
export function distribution(values) {
  if (!values.length || values.some(v => !Number.isFinite(v) || v < 0)) throw new Error('Invalid samples');
  const sorted = [...values].sort((a, b) => a - b);
  const percentile = p => sorted[Math.ceil(p * sorted.length) - 1];
  return { n: values.length, min: sorted[0], p50: percentile(.50), p95: percentile(.95), p99: percentile(.99), max: sorted.at(-1) };
}
