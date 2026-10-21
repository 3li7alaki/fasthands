# fasthands

> Several Claude Max accounts, one Claude Code. Spend the quota that expires first.

[![License: MIT](https://img.shields.io/badge/license-MIT-black)](LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-support-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/3li7alaki)

Each Claude Max account gets a 5 hour window and a weekly window, and whatever weekly
quota you did not use is gone when that week resets. With two or three accounts, the
usual move is to log out and back in when one runs dry, which throws away whatever the
others had left and interrupts every open session.

fasthands is a small CLI that keeps every account's login, watches their usage, and
switches Claude Code to the right one live: open `claude` sessions carry on with the
new account on their next request. One static binary, no dependencies, macOS and Linux.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/3li7alaki/fasthands/main/install.sh | sh
```

Installs to `~/.local/share/fasthands` and links `~/.local/bin/fasthands`. Every push to
`main` republishes the binaries, so rerunning the installer updates it.
`install.sh --uninstall` removes it.

## What it looks like

```
$ fasthands status
personal  *  62%  20:29  60%  Tue 05:59  +23.3  0s ago  max default_claude_max_5x
work          8%  22:50   3%  Tue 02:00  -36.1  0s ago  max default_claude_max_5x

$ fasthands pick
switch personal -> work: rule 3: work resets Tue 02:00, at least 1h before personal
```

## Setup

Log in to Claude Code as each account once and capture it:

```sh
fasthands add --alias personal   # while logged in as the first account
# /login as the next account in Claude Code, then
fasthands add --alias work
```

Then feed it Claude Code's status line, so it sees live usage and can switch on its own.
In your status line script, before anything else reads stdin:

```sh
input=$(cat)
alias=$(printf '%s' "$input" | fasthands hook statusline)   # prints the active alias
```

The hook always exits 0, never writes to stderr, and takes a few milliseconds, so it
cannot break your status line.

## Commands

| Command | What it does |
|---|---|
| `add [--alias NAME]` | Capture the current Claude Code login as an account. Rerun to rename. |
| `ls` | List accounts. |
| `switch ALIAS [--wait D]` | Make ALIAS the live login now. `--wait` lets running turns finish first. |
| `status` | Usage per account: 5h and weekly windows, resets, pace, plan. Refreshes data older than 10 min. |
| `refresh [ALIAS...]` | Fetch usage now. |
| `priority ALIAS...` | Your preferred order, used to break ties. `--clear` removes it. |
| `disable ALIAS` | Park an account without deleting its saved login. |
| `enable ALIAS` | Make a parked account available for switching again. |
| `rename OLD NEW` | Change an account alias without changing its saved login. |
| `pick` | Show what the picker would do, and why. Changes nothing. |
| `auto on\|off` | Pause or resume automatic switching. |
| `auto --once` | Run the picker once and act on it. The status line hook does this for you. |

Every command takes `--json`.

## How switching works

fasthands writes the chosen account's login where Claude Code keeps it (the Keychain on
macOS, `~/.claude/.credentials.json` on Linux) and its identity into Claude's config,
holding Claude Code's own credential locks while it does. Running sessions pick the new
login up the same way they pick up a `/login`: on their next request on Linux, within
about 30 seconds on macOS. Nothing restarts.

Each account's login is kept in its own backup (Keychain or a 0600 file). When an idle
account's access token expires, fasthands refreshes it, saving the new login before
using it. It never refreshes the account that is live in Claude Code: Claude owns that
one.

## How it picks

Each account has a 5h window and a weekly window, and any weekly quota you have not
used is gone when the week resets. So fasthands spends the quota that expires first,
the way a warehouse ships the stock that spoils first (FEFO: first expired, first out).

1. **Eligible:** every window you use is under 80% (the 90% threshold minus a 10 point
   margin, so an account you just left does not look free again at 89%).
2. **Rank:** eligible accounts by soonest weekly reset. Resets within an hour of each
   other count as a tie, broken by your `priority` order, then by weighted headroom.
3. **Switch** when the live account hits 90% on any window, or another eligible account
   resets at least an hour sooner. Not within 5 minutes of the last switch, unless the
   live account is at 100%. Each account has its own prompt cache, so a switch that only
   chases an earlier reset waits until no session is mid-turn; one forced by usage goes
   at once.
4. **All full:** move to whichever account has room left, or, if none has, the one
   whose binding window resets first.
5. **Check before acting:** fetch the target's usage fresh and decide again, since it
   may have been used elsewhere.

### Worked example

From the `status` above:

| | personal (live) | work |
|---|---|---|
| 5h used | 62% | 8% |
| weekly used | 60% | 3% |
| weekly resets | Tue 05:59 | Tue 02:00 |

- Is work eligible? Its highest window is 8%, under 80%. Yes.
- Does personal need to leave on usage? Its highest window is 62%, under 90%. No.
- Does work reset sooner? Tue 02:00 is about 4 hours before Tue 05:59, more than the
  1 hour tie. Yes, so switch to work.

Why: work's 97% of weekly headroom expires at 02:00. Every hour spent on personal
instead lets some of it go unused, while personal's quota keeps until 05:59. After 02:00
work's week restarts and its next reset is a week away, so personal becomes the one that expires
first and fasthands moves back.

**Pace** in `status` is how far ahead of an even spend the weekly window is:
`used - 100 * elapsed / week`. personal at 60% with about 2.6 of 7 days elapsed:
`60 - 100 * 2.6 / 7 = +23`. It is shown, never used to switch: as a trigger it would
move you off the account whose quota is about to expire.

Max 5x and 20x accounts can mix. Headroom ties are weighted by plan size (5 and 20), so
half of a 20x account beats nine tenths of a 5x one.

## Usage data and limits

Usage comes from two places: Claude Code's status line (free, live, only for the
account in use) and Anthropic's usage endpoint (for the rest). The endpoint allows
roughly 30 requests per account per hour; fasthands caps itself at 20 and backs off
for the server's `Retry-After` plus 15 minutes when it is told to slow down.

## Files

| Path | What |
|---|---|
| `~/.local/state/fasthands/accounts.json` | Accounts, aliases, plan, priority. No secrets. |
| `~/.local/state/fasthands/usage.json` | Usage windows and request budget. No secrets. |
| `~/.local/state/fasthands/auto.log` | One line per automatic switch. |
| Keychain service `fasthands` (macOS) or `~/.local/share/fasthands/credentials/` (Linux) | Login backups. |

`FASTHANDS_HOME` moves all of it under one directory.

## What it is not

- Not a way to share one subscription between people. Every account is yours, logged in
  by you.
- Not a proxy. Requests go from Claude Code to Anthropic exactly as before; fasthands
  only changes which login Claude Code holds.
- Not a usage meter for API keys, Bedrock or Vertex. It reads Claude subscription
  windows only.

## Credits

The credential locking, the usage endpoint's measured rate limit, and the shape of the
Claude Code login were worked out first by
[claude-swap](https://github.com/realiti4/claude-swap).

## Support

fasthands is free and MIT licensed, and there is no pricing page. If it saved you an
afternoon, that is worth about the price of a coffee.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/3li7alaki)

Need something like this built for your own stack? Commissions are open at
[ko-fi.com/3li7alaki](https://ko-fi.com/3li7alaki).

## License

MIT. See [LICENSE](LICENSE).
