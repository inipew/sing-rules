# Go rule-set generator

The scheduled GitHub Actions build uses the Go implementation in `cmd/build-rules`.
The previous `build_rules.py` is retained temporarily as a reference during migration; it is
not invoked by the workflow.

## Requirements

- Go version declared in `go.mod` (the workflow pins Go 1.26.8).
- A compatible sing-box CLI binary.
- Network access to the configured rule sources.

## Run

From the repository root:

```sh
go test ./...
go run ./cmd/build-rules --verbose
```

Supported flags:

- `--skip-download`: use source files already present in the output directory.
- `--only-compile`: only compile existing JSON rule sets to SRS.
- `--dry-run`: log planned downloads and sing-box commands without changing files.
- `--fail-fast`: stop after a failed source download.
- `--workers N`: maximum concurrent source downloads.
- `--verbose` / `-v`: include debug-level runtime information.

Environment variables:

- `SINGBOX_BIN`: sing-box executable (default `./sing-box`).
- `OUTPUT_DIR`: directory for downloaded/generated files (default current directory).
- `SINGBOX_VERSION`: version label included in the build log.
- `GITHUB_STEP_SUMMARY`: optional GitHub Actions summary file.
- `GITHUB_ACTIONS`: enables workflow annotations and log groups when set to `true`.

## Data and compatibility notes

- Indonesia country GeoIP is sourced from MetaCubeX `meta-rules-dat`.
- Indonesia ASN CIDRs remain sourced separately from `malikshi/route`; ASN data is not interchangeable
  with country GeoIP data.
- `geoip-onlyid.json` continues to combine the ASN and country CIDR inputs, collapse overlapping
  and adjacent sibling prefixes, and apply the existing port list.
- `wa_local.json` continues to combine Facebook IP CIDRs with the existing port list.
- Generated rule-set JSON retains sing-box rule-set version 3; source GeoIP JSON may use a different
  input version and is passed through the sing-box formatter before compilation.

Downloads are validated before being atomically moved into place. Invalid or empty GeoIP source
responses do not overwrite the last usable file. The generator uses only the Go standard library.
