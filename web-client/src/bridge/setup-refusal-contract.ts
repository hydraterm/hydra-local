/** Browser-local stable refusal, emitted only when an adapter explicitly denies setup.
 * The legacy state is retained for hosted presentation compatibility; HTTP/payment policy stays in its adapter. */
export type SetupRefusalState = 'access_required' | 'entitlement_required'

export class StableSetupRefusal extends Error {
  constructor(readonly state: SetupRefusalState = 'access_required', message = 'remote_access_required') {
    super(message)
    this.name = 'StableSetupRefusal'
  }
}

/** Nominal and closed: arbitrary error-shaped objects cannot select a controller state. */
export function isStableSetupRefusal(error: unknown): error is StableSetupRefusal {
  return error instanceof StableSetupRefusal &&
    (error.state === 'access_required' || error.state === 'entitlement_required')
}
