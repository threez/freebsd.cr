# freebsd

Crystal bindings for FreeBSD.

- **`freebsd/capsicum`** — [Capsicum] kernel capability mode (`cap_enter`,
  fd rights, `pdfork` process descriptors). Use this alone when you only need
  sandboxing without the libcasper service framework.

- **`freebsd/casper`** — [libcasper] services built on top of
  `freebsd/capsicum`: DNS, file, net, syslog, pwd/grp/sysctl. Lets a sandboxed
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

[Capsicum]: https://www.cl.cam.ac.uk/research/security/capsicum/
[libcasper]: https://man.freebsd.org/cgi/man.cgi?query=libcasper
[libbsm]: https://man.freebsd.org/cgi/man.cgi?query=libbsm
[OpenBSM]: https://github.com/openbsm/openbsm
[OCSF]: https://schema.ocsf.io

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises `UnsupportedPlatformError`.

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

## Contributing

1. Fork it (<https://github.com/threez/freebsd.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Open a Pull Request

## Contributors

- [Vincent Landgraf](https://github.com/threez) — creator and maintainer
