# fasthands

Single-binary Go CLI, stdlib only. Scaffolded by `cli new`, and `cli check .` is the
gate that keeps it on the canonical layout.

## Layout

    cli/                  the Go module, named fasthands
      cmd/fasthands/       main package, argument parsing lives here
      internal/           everything else
      internal/version/   Version, set by release ldflags, printed by --version
    install.sh            curl installer, fetches the rolling `latest` release
    .github/workflows/    ci.yml (gofmt, vet, build, test), release.yml (4 binaries)

## Rules

- No third-party dependencies. `cli/go.mod` must stay free of `require`. Stdlib `flag`
  plus a switch on `os.Args` is the whole command layer, and it is enough.
- Every command takes `--json`. Human output is never the integration protocol.
- Releases roll: every push to main rebuilds four binaries and republishes the single
  `latest` release. No tags, no semver, so nothing to bump by hand.
- Never write an em dash or an en dash, anywhere in this repo.
- Run `cli check .` before committing. Fix what it reports rather than editing the rule.

## Gates

    cd cli && gofmt -l . && go vet ./... && go build ./... && go test ./... -count=1
