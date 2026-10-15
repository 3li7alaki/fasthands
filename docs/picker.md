# Picker

Decided 2026-10-15. Slice 5 implements this; the README explains it with a worked
example once it ships.

## Problem

N Claude Pro accounts, each with a rolling 5h window, a weekly window with its own reset
time, and per-model weekly windows. Weekly quota left unused at reset is gone. Goal: never
hit a limit, waste as little weekly quota as possible, never flap.

## Rule

Per account, for every window the user actually uses (5h, weekly, the per-model weekly
windows of the models in use): `used` in 0..1 and `resets_at`.

1. Eligible: every used window is at least `hysteresis` below `threshold`
   (defaults 0.10 and 0.90, so under 0.80).
2. Rank eligible accounts by soonest weekly reset (FEFO: first expired, first out).
   Resets within `tie` (1h) of each other: more weekly headroom wins.
3. Switch when, outside the `cooldown` (5 min; bypassed when the active account is at
   its limit):
   - the active account's binding window (its highest `used`) reaches `threshold`, or
   - an eligible account's weekly reset is at least `tie` sooner than the active one's.
4. Every account at or over `threshold`: move to the account whose binding window
   resets first, if it resets at least 5 min sooner than the active one's.
5. Refresh the chosen candidate's usage before acting (it may have been used elsewhere,
   such as a VPS on a setup-token) and re-run the rule on the fresh numbers.

A `resets_at` already in the past means unknown, never "soonest". Unknown sorts last.

## Why

- FEFO is the standard issuing rule for perishable stock: it minimises expiry waste.
- One ranking axis with one one-way margin. claude-swap measured 47 credential rewrites
  in 3.9h when two ranking axes mixed (`autoswitch.py`, `_recovery_is_useful`).
- Threshold, hysteresis and cooldown match claude-swap's defaults (90, 10, 300s).
- Pace (`used - elapsed/week`) is display only in `status`. As a trigger it would move
  off the soonest-resetting account and waste the quota about to expire; every other
  case is already covered by rule 2.

## Ceiling

Assumes every account is the same plan. A Max account makes `used` fractions
incomparable; the upgrade is normalising by plan size once that size is known.

## Sources

- FEFO: https://www.shipbob.com/blog/fefo/
- claude-swap autoswitch (realiti4/claude-swap at 7d30991, src/claude_swap/autoswitch.py)
- Budget pacing: https://arxiv.org/pdf/1506.05851
- Limit-aware routing: https://docs.litellm.ai/docs/routing
