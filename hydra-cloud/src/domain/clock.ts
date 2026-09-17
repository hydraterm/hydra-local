export interface Clock {
  nowMs(): number
}
export const systemClock: Clock = { nowMs: () => Date.now() }
