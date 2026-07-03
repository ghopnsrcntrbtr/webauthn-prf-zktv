/** Overwrites a typed-array view with zeros. Best-effort in JS — see SECURITY.md. */
export function zeroize(view: Uint8Array): void {
  view.fill(0);
}
