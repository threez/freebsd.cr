# FreeBSD::Audit

BSM audit helpers for Crystal on FreeBSD: write structured audit events to the
FreeBSD audit subsystem using `libbsm`, with event types mapped from the
[OCSF schema](https://schema.ocsf.io).

```crystal
require "freebsd/audit"
```

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises
> `FreeBSD::Audit::UnsupportedPlatformError`.

## Quick start

```crystal
require "freebsd/audit"

# High-level: event class + activity in one call
FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::Authentication::Activity::Logon) do |r|
  r.subject uid: 80_u32
  r.text "user=admin"
  r.address "203.0.113.42"
  r.return_failure Errno::EACCES
end
```

## OCSF event mapping

BSM event numbers are derived directly from [OCSF class UIDs]:

```
bsm_event_number = ocsf_class_uid + 40000
```

| OCSF class | OCSF UID | BSM event |
|------------|----------|-----------|
| File System Activity | 1001 | 41001 |
| Process Activity | 1007 | 41007 |
| Authentication | 3002 | 43002 |
| HTTP Activity | 4002 | 44002 |
| DNS Activity | 4003 | 44003 |
| API Activity | 6003 | 46003 |
| File Remediation Activity | 7002 | 47002 |

All 74 cross-platform OCSF classes are mapped. See `AUE` enum in
[`aue.cr`](aue.cr) for the full list.

[OCSF class UIDs]: https://schema.ocsf.io/api/1.3.0/classes

## Activity enums

Each OCSF class with a meaningful activity vocabulary has a matching Crystal
enum under its own namespace. Each activity value carries a `#aue` method
that returns the parent `AUE` — so `write_activity` can look up the event
class automatically.

```crystal
# Authentication (OCSF 3002 → BSM 43002)
FreeBSD::Audit::Authentication::Activity::Logon      # activity_id = 1
FreeBSD::Audit::Authentication::Activity::Logoff     # activity_id = 2

# File System Activity (OCSF 1001 → BSM 41001)
FreeBSD::Audit::FileSystemActivity::Activity::Create # activity_id = 1
FreeBSD::Audit::FileSystemActivity::Activity::Read   # activity_id = 2
FreeBSD::Audit::FileSystemActivity::Activity::Delete # activity_id = 4
FreeBSD::Audit::FileSystemActivity::Activity::Open   # activity_id = 14

# Network Activity (OCSF 4001 → BSM 44001)
FreeBSD::Audit::NetworkActivity::Activity::Open      # activity_id = 1
FreeBSD::Audit::NetworkActivity::Activity::Refuse    # activity_id = 5

# API Activity (OCSF 6003 → BSM 46003)
FreeBSD::Audit::ApiActivity::Activity::Create        # activity_id = 1
FreeBSD::Audit::ApiActivity::Activity::Delete        # activity_id = 4
```

Available activity modules:

| Module | OCSF class |
|--------|------------|
| `Authentication::Activity` | 3002 |
| `AccountChange::Activity` | 3001 |
| `FileSystemActivity::Activity` | 1001 |
| `ProcessActivity::Activity` | 1007 |
| `ScheduledJobActivity::Activity` | 1006 |
| `NetworkActivity::Activity` | 4001 |
| `HttpActivity::Activity` | 4002 |
| `DnsActivity::Activity` | 4003 |
| `ApiActivity::Activity` | 6003 |
| `ApplicationLifecycle::Activity` | 6002 |

All activity enums use `Unknown = 0` and `Other = 99` per OCSF convention.

## write_activity vs write

`Event.write_activity` is the preferred API. It resolves the parent event class
from the activity value and writes the `activity_id` token automatically:

```crystal
FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::HttpActivity::Activity::Refuse) do |r|
  r.subject
  r.text "path=/admin method=POST"
  r.address "198.51.100.4"
  r.return_failure Errno::EACCES
end
```

Use the lower-level `Event.write` when you want full control or when writing
an event class that has no activity enum:

```crystal
FreeBSD::Audit::Event.write(FreeBSD::Audit::AUE::VulnerabilityFinding) do |r|
  r.text "cve=CVE-2024-1234 severity=high"
  r.return_success
end
```

## Token reference

| Method | BSM token | Notes |
|--------|-----------|-------|
| `r.subject(uid:, pid:, session:, terminal:)` | `subject32` / `subject32_ex` | All params optional; defaults to current process |
| `r.text(message)` | `text` | Arbitrary UTF-8 string |
| `r.address(ip)` | `in_addr` / `in_addr_ex` | IPv4 or IPv6 string |
| `r.return_success(ret: 0)` | `return32` status=0 | |
| `r.return_failure(errno: 0)` | `return32` status=1 | Also accepts `Errno` directly: `r.return_failure(Errno::EACCES)` |
| `r.activity_id(id, name)` | `text` | Written automatically by `write_activity`; also accepts a typed Activity value |

Recommended token order: `subject` → `text` → `address` → `return_*`.

## discard / discard_activity

Both `Event.write` and `Event.write_activity` have `discard` counterparts that
build tokens without committing to the audit trail. Useful for testing without
a live `auditd`:

```crystal
FreeBSD::Audit::Event.discard_activity(FreeBSD::Audit::Authentication::Activity::Logon) do |r|
  r.text "dry run"
  r.return_failure
  r.write_failures # => 0
end
```

## Strict mode

By default token-write failures increment `record.write_failures` and
execution continues. Pass `strict: true` to raise `TokenWriteError` on the
first failure instead:

```crystal
FreeBSD::Audit::Event.write_activity(
  FreeBSD::Audit::FileSystemActivity::Activity::Delete,
  strict: true,
) do |r|
  r.text "path=/etc/passwd"
  r.return_failure
end
```

## Registering events in /etc/security/audit_event

Add the OCSF-mapped events you use to `/etc/security/audit_event` so that
`praudit` and `auditreduce` resolve them by name:

```
# /etc/security/audit_event  (format: number:name:description:class)
43002:OCSF_authentication:OCSF authentication event:aa
41001:OCSF_file_system_activity:OCSF file system activity:aa
44001:OCSF_network_activity:OCSF network activity:aa
46003:OCSF_api_activity:OCSF API activity:aa
```

The event class `aa` controls preselection. Enable it in
`/etc/security/audit_control`:

```
flags:aa
```

## Prerequisites

- FreeBSD with `auditd(8)` running and the `aa` event class enabled
- `libbsm` ships with FreeBSD base — no ports or packages required
- The writing process needs access to the audit pipe; typically root or the
  `audit` group

## Reading the audit trail

```sh
# Human-readable output:
praudit /var/audit/current

# Filter to authentication events only:
auditreduce -e 43002 /var/audit/current | praudit

# Filter to all OCSF events (41001–47004):
auditreduce -e 41001,43002,44001,46003 /var/audit/current | praudit

# Follow in real time:
praudit -f /dev/auditpipe
```
