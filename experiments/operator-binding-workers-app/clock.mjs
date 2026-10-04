// Synthetic Host timer only. Actual Kernel owns scheduling, admission and shutdown.
export function clock(operation, callback, value) {
  if (operation === 0) return performance.now();
  if (operation === 1) return setTimeout(callback, value);
  if (operation === 2) { clearTimeout(value); return 0; }
  throw new Error("unknown proof clock operation");
}
