# freebsd

Crystal bindings for FreeBSD system libraries — opt-in by sub-library.

Each sub-library is a separate require. `require "freebsd"` alone pulls in
nothing but the `FreeBSD::VERSION` constant — no C libraries are linked until
you explicitly require the sub-library you need:

```crystal
require "freebsd/pkg"       # libpkg — package management
require "freebsd/capsicum"  # Capsicum — capability mode sandboxing
require "freebsd/casper"    # libcasper — privilege-separated services
require "freebsd/nvlist"    # libnv — named-value lists
require "freebsd/privdrop"  # setuid/setgid/chroot helpers
require "freebsd/audit"     # libbsm — BSM audit event writer
```

Mix and match only what your application needs.

---

- **`freebsd/pkg`** — [libpkg] package management. Query installed packages,
  search repository catalogs, install/remove/upgrade packages via the jobs API,
  manage annotations and locks, register event callbacks for progress reporting.

- **`freebsd/capsicum`** — [Capsicum] kernel capability mode (`cap_enter`,
  fd rights, `pdfork` process descriptors). Use this alone when you only need
  sandboxing without the libcasper service framework.

- **`freebsd/casper`** — [libcasper] services built on top of
  `freebsd/capsicum`: DNS, file, net, syslog, pwd/grp/sysctl, and a
  pure-Crystal audit helper for capsicum-safe BSM writes. Lets a sandboxed
  process delegate privileged work to a trusted helper. Includes transparent
  integrations for Crystal's stdlib (`Socket::Addrinfo`, `File`, `Log`).

- **`freebsd/nvlist`** — libnv encoder/decoder. Named-value lists used
  internally by libcasper and the FreeBSD kernel for structured data exchange.

- **`freebsd/privdrop`** — privilege-drop helpers (`setuid`, `setgid`,
  `setgroups`, `initgroups`, `chroot`) with correct-ordering documentation and
  environment scrubbing. Use before entering capability mode to relinquish
  root cleanly.

- **`freebsd/audit`** — [libbsm] / [OpenBSM] audit event writer. Lets Crystal
  applications emit structured BSM audit records to FreeBSD's audit subsystem.
  Event types are mapped directly from [OCSF] class UIDs (`bsm = ocsf_uid + 40000`),
  with per-class activity enums and a `write_activity` API that resolves the
  event class automatically from the activity value.

[libpkg]: https://man.freebsd.org/cgi/man.cgi?query=pkg
[Capsicum]: https://www.cl.cam.ac.uk/research/security/capsicum/
[libcasper]: https://man.freebsd.org/cgi/man.cgi?query=libcasper
[libbsm]: https://man.freebsd.org/cgi/man.cgi?query=libbsm
[OpenBSM]: https://github.com/openbsm/openbsm
[OCSF]: https://schema.ocsf.io

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises `UnsupportedPlatformError`.

## Versioning

Versions follow `<freebsd_major>.<minor>.<update>` — the first number tracks
the FreeBSD major release the bindings target (e.g. `15.x.x` for FreeBSD 15),
the second is a feature increment, and the third is this shard's own update
counter (bug fixes, lint/tooling changes, etc.), not a FreeBSD point-release
number. The initial release for a given FreeBSD major version starts at
`<major>.0.0` (e.g. `15.0.0` = first release targeting FreeBSD 15.0-RELEASE).

## Installation

Add to `shard.yml`:

```yaml
dependencies:
  freebsd:
    github: threez/freebsd.cr
```

then `shards install`.

## Sub-libraries

See each sub-library's README for full API documentation and examples:

- [`freebsd/pkg`](src/freebsd/pkg.cr)
- [`freebsd/capsicum`](src/freebsd/capsicum/README.md)
- [`freebsd/casper`](src/freebsd/casper/README.md)
- [`freebsd/nvlist`](src/freebsd/nvlist/README.md)
- [`freebsd/privdrop`](src/freebsd/privdrop/README.md)
- [`freebsd/audit`](src/freebsd/audit/README.md)

## Development

```sh
shards install
crystal spec
```

On non-FreeBSD hosts most specs are marked `pending`. To exercise the real
bindings, run the suite on a FreeBSD 14/15 host or VM (FreeBSD 15 is used in
development; FreeBSD 14 is also supported).

### Make tasks

The `Makefile` wraps the common workflows:

| Task             | What it does                                                        |
| ---------------- | ------------------------------------------------------------------- |
| `make all`       | `clean fmt lint docs spec` — the full local check.                  |
| `make fmt`       | Format the code (`crystal tool format`).                            |
| `make fmtcheck`  | Verify formatting without writing (`crystal tool format --check`).  |
| `make lint`      | Run ameba (builds it via `shards install` if needed).               |
| `make fix`       | Run ameba with `--fix` to auto-correct findings.                    |
| `make spec`      | Run the spec suite (`crystal spec -v`).                             |
| `make docs`      | Build the API docs into `docs/`.                                    |
| `make version`   | Sync the `VERSION` constant in `src/` to `shard.yml`'s version.     |
| `make tag`       | Create the annotated git tag `vX.Y.Z` from `shard.yml`'s version.   |

**Releasing:** bump the `version:` field in `shard.yml` first, then run
`make version` so the `VERSION` constant in `src/freebsd.cr` stays in sync —
they must match. Commit both together (`bump version to X.Y.Z`), and optionally
`make tag` to tag the release.

## Contributing

1. Fork it (<https://github.com/threez/freebsd.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Open a Pull Request

## Contributors

- [Vincent Landgraf](https://github.com/threez) — creator and maintainer
