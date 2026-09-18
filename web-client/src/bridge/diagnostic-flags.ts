export type DiagnosticQueryFlag = 'inspect' | 'metrics'

/** Developer diagnostics are opt-in even in production builds. A normal page load must not install globals that
 * expose account-scoped workspace/session metadata to DevTools. */
export function diagnosticQueryFlag(
  flag: DiagnosticQueryFlag,
  search = typeof location !== 'undefined' ? location.search : '',
): boolean {
  try {
    return new URLSearchParams(search).get(flag) === '1'
  } catch {
    return false
  }
}
