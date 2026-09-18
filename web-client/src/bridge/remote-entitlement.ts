import { StableSetupRefusal } from './setup-refusal-contract.js'

export const REMOTE_ENTITLEMENT_REQUIRED_ERROR = 'remote_entitlement_required'

/** A paid-plan refusal is a stable authorization state, not a network failure to retry in a loop. */
export class RemoteEntitlementRequired extends StableSetupRefusal {
  constructor() {
    super('entitlement_required', REMOTE_ENTITLEMENT_REQUIRED_ERROR)
    this.name = 'RemoteEntitlementRequired'
  }
}

export function isRemoteEntitlementRequiredResponse(status: number, body: unknown): boolean {
  if (status !== 402 || !body || typeof body !== 'object' || Array.isArray(body)) return false
  const record = body as Record<string, unknown>
  return Object.keys(record).length === 1 && record.error === REMOTE_ENTITLEMENT_REQUIRED_ERROR
}

export function throwIfRemoteEntitlementRequired(status: number, body: unknown): void {
  if (isRemoteEntitlementRequiredResponse(status, body)) throw new RemoteEntitlementRequired()
}

export function isRemoteEntitlementRequired(error: unknown): error is RemoteEntitlementRequired {
  return error instanceof RemoteEntitlementRequired
}
