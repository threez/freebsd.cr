# Fixture for FreeBSD::Sandbox.prime_tz_data! / .prime_tls_context! called
# standalone — no FreeBSD::Sandbox.define anywhere in this program. Proves
# both entry points work independent of the `Sandbox.define` macro (needed by
# programs whose other pre-sandbox setup must run before `Sandbox.define`
# starts, e.g. business/id's KMS/mail HTTP clients — see those two methods'
# doc comments) and that priming twice (standalone, then again as if from a
# `tls_context`/`tz_data` directive later in the same program) is a safe
# no-op rather than a double-build or a raise.

require "../../../src/freebsd/sandbox"

FreeBSD::Sandbox.prime_tz_data!
FreeBSD::Sandbox.prime_tls_context!

# Simulates a directive re-priming later in the same program.
FreeBSD::Sandbox.prime_tz_data!
FreeBSD::Sandbox.prime_tls_context!

builder = FreeBSD::Sandbox.http_client_builder(timeout: 5.seconds)
client = builder.call(URI.parse("https://example.com"), 5.seconds)
STDOUT.puts(client.is_a?(HTTP::Client) ? "builder-ok" : "builder-ERROR")

STDOUT.puts(Time.local.is_a?(Time) ? "tz-ok" : "tz-ERROR")

STDOUT.puts "done"
STDOUT.flush
