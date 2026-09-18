// Provider-neutral account/session boundary used by the Remote controller.
// Concrete hosted authentication, cookies and SDK integrations remain in auth-provider.ts.

export type IdentityReverificationFailureCode =
  | 'reverification_unavailable'
  | 'reverification_method_unavailable'
  | 'reverification_start_failed'
  | 'reverification_failed'
  | 'reverification_timed_out'
  | 'reverification_ui_unavailable'

export interface Session {
  accountId: string
  /** Opaque credential or adapter marker for control-plane calls, never terminal data.
   * The configured adapter interprets it; consumers must not persist or log it. */
  credential: string
}

/** Vendor-neutral continuation exposed to the browser UI. Hydra deliberately supports only the two
 * possession factors that belong to optional authenticator-app enrollment; phone/email device-trust
 * challenges remain separate provider states and must never be mislabeled as enrolled MFA. */
export type AuthSecondFactorStrategy = 'totp' | 'backup_code'

export type ManagedSignInResult =
  | { kind: 'complete' }
  | {
      kind: 'second_factor'
      strategies: readonly AuthSecondFactorStrategy[]
      /** Present only after this exact strategy was attempted and the identity provider kept the attempt sessionless. */
      rejectedStrategy?: AuthSecondFactorStrategy
    }
  | { kind: 'client_trust' }

/** A normal, incomplete sign-in state. Throwing across the AuthProvider port keeps Session honest: callers
 * receive a Session only after the identity provider has completed and activated the second factor. */
export class AuthSecondFactorRequiredError extends Error {
  constructor(
    readonly strategies: readonly AuthSecondFactorStrategy[],
    readonly rejectedStrategy?: AuthSecondFactorStrategy,
  ) {
    super(rejectedStrategy === 'backup_code'
      ? 'That recovery code was not accepted. It may be invalid, already used, or from a replaced set.'
      : rejectedStrategy === 'totp'
        ? 'That authenticator code was not accepted. Check it and try again.'
        : strategies.includes('totp')
          ? 'Please insert authenticator code.'
          : 'Please enter a recovery code.')
    this.name = 'AuthSecondFactorRequiredError'
  }
}

/** A provider's new-device trust challenge is distinct from user-enrolled TOTP and does not
 * represent a completed sign-in or permission to create a session. */
export class AuthClientTrustRequiredError extends Error {
  constructor() {
    super('This new device needs an additional verification step. Try a trusted device or contact support.')
    this.name = 'AuthClientTrustRequiredError'
  }
}

/** A fixed, vendor-neutral failure for an authentication capability that the configured managed-auth client
 * does not expose. Missing methods must never collapse into `null`: callers would otherwise present a retry or
 * Client Trust state even though no provider request was made. */
export class AuthCapabilityUnavailableError extends Error {
  constructor(capability: 'password_sign_in' | 'second_factor' | 'sign_in_continuation') {
    const message = capability === 'password_sign_in'
      ? 'Password sign-in is not available in the configured authentication client.'
      : capability === 'second_factor'
        ? 'Additional sign-in verification is not available in the configured authentication client.'
        : 'The pending sign-in verification method is not supported.'
    super(message)
    this.name = 'AuthCapabilityUnavailableError'
  }
}

/** A session-exchange that REACHED the cloud but was REJECTED (non-2xx) or returned an unusable body (no
 * accountId). Distinct from a retry-friendly no-token/no-user (the user is mid-sign-in) — this is a real
 * config/auth failure worth surfacing. Content-blind: the message is mapped from the HTTP STATUS only, never
 * any provider credential, cookie, or response body. The controller can display a safe reason. */
export class AuthExchangeError extends Error {
  constructor(readonly status: number) {
    super(exchangeMessage(status))
    this.name = 'AuthExchangeError'
  }
}

/** A server logout that could not be confirmed. The response body and underlying network error are
 * deliberately discarded: callers only receive this fixed, content-blind error. */
export class AuthLogoutError extends Error {
  constructor() {
    super('server sign-out could not be confirmed')
    this.name = 'AuthLogoutError'
  }
}

export interface AccountDeletionResult {
  /** Hydra product data is already inaccessible/purged. True means managed-auth cleanup is still retrying. */
  identityDeletionPending: boolean
}

export type AuthAccountDeletionReasonCode =
  | IdentityReverificationFailureCode
  | 'reverification_session_unavailable'
  | 'reverification_proof_unavailable'
  | 'reverification_unknown'
  | 'account_changed'
  | 'deletion_request_failed'

/** Fixed, content-blind account-deletion failure. Never carries a provider token or response body. */
export class AuthAccountDeletionError extends Error {
  constructor(
    message = 'Could not confirm account deletion. Check your connection and try again.',
    readonly status = 0,
    readonly reasonCode: AuthAccountDeletionReasonCode = 'deletion_request_failed',
  ) {
    super(message)
    this.name = 'AuthAccountDeletionError'
  }
}

/** Neutral user cancellation from the managed reverification dialog. */
export class AuthAccountDeletionCancelledError extends Error {
  constructor() {
    super('Account deletion was cancelled.')
    this.name = 'AuthAccountDeletionCancelledError'
  }
}

/** The authoritative cloud tombstone says this account can never be restored or exchanged again. */
export class AuthAccountDeletedError extends Error {
  constructor() {
    super('This Hydra account was deleted. You are signed out.')
    this.name = 'AuthAccountDeletedError'
  }
}

/** A real browser without a cross-document mutex cannot safely order logout against a newer account exchange. */
export class AuthCoordinationError extends Error {
  constructor() {
    super('Secure account switching requires a browser with Web Locks support. Update your browser and try again.')
    this.name = 'AuthCoordinationError'
  }
}

/** The operation lost authority because another document published logout while it was in flight. */
export class AuthSupersededError extends Error {
  constructor() {
    super('Authentication was paused because another tab signed out. Try again.')
    this.name = 'AuthSupersededError'
  }
}

/** Map an HTTP status to an actionable, content-blind reason for a failed session-exchange. Exported so a
 * coherence test can prove every emitted message still maps to a remediation hint (no silent drift). */
export function exchangeMessage(status: number): string {
  if (status === 401 || status === 403) return 'sign-in was rejected (the account or app may not be authorized)'
  if (status === 0) return 'could not reach the sign-in service (network or CORS)' // fetch() rejection surrogate
  if (status === 299) return 'sign-in completed, but the session cookie was not accepted (check cookie settings)'
  if (status >= 500) return 'the sign-in service had an error — please try again'
  return `sign-in failed (status ${status})`
}

export interface AuthProvider {
  /** True when this provider holds the cross-document auth lock across its own settle+auth operation. */
  readonly coordinatesAuthSession?: boolean
  /** Interactive sign-in; returns a verified session or null when sign-in did not complete. */
  signIn(): Promise<Session | null>
  /** Interactive registration followed by sign-in; the provider owns its supported workflow. */
  signUp(): Promise<Session | null>
  /** After restore() returns null, complete an existing authenticated identity continuation without
   * prompting or redirecting. Return null when none exists; incomplete factors remain sessionless. */
  resumeIdentitySession(): Promise<Session | null>
  /** Restore and revalidate an existing session without prompting. */
  restore(): Promise<Session | null>
  /** Current session without I/O, if already signed in/restored. */
  current(): Session | null
  /** Sign out and invalidate the current session through the configured authority. */
  signOut(): Promise<void>
  /** Permanently delete the signed-in account. Implementations must own fresh human reverification and the
   * shared cross-document auth lock; settings code must never perform this destructive fetch directly. */
  deleteAccount?(expectedAccountId: string): Promise<AccountDeletionResult>
  /** Whether a prior server logout is still unconfirmed. Optional for non-cookie/dev providers. */
  hasPendingSignOut?(): boolean
  /** Wait for the shared auth lock and, only if a marker exists inside it, finish that logout. Returns whether
   * this caller observed/settled a pending logout. It never initiates logout when no marker exists. */
  settlePendingSignOut?(): Promise<boolean>
  /** Notify a live controller immediately when this or another same-origin document publishes logout intent. */
  onPendingSignOut?(handler: (state: 'pending' | 'cleared') => void): () => void
  /** Notify other same-origin controllers only after deletion is authoritatively committed. */
  onAccountDeleted?(handler: () => void): () => void
  /** Notify other same-origin controllers when the shared authenticated context changes. */
  onAuthContextChanged?(handler: () => void): () => void
  /** Custom first-party sign-in surface: email/password entered in Hydra UI, the identity provider verifies. */
  signInWithPassword?(email: string, password: string): Promise<Session | null>
  /** Finish a pending optional authenticator-app sign-in. No Session exists until this resolves successfully. */
  completeSignInSecondFactor?(strategy: AuthSecondFactorStrategy, code: string): Promise<Session | null>
  /** Custom first-party sign-up surface: email/password entered in Hydra UI, the identity provider creates the user when allowed. */
  signUpWithPassword?(name: string, email: string, password: string): Promise<Session | null>
  /** Complete a pending email-code sign-up started by signUpWithPassword. */
  verifySignUpCode?(code: string): Promise<Session | null>
  /** Optional social sign-in; the identity provider owns redirect and verification. */
  signInWithOAuth?(provider: 'google' | 'github' | 'apple' | 'facebook', mode: 'sign-in' | 'sign-up'): Promise<Session | null>
}
