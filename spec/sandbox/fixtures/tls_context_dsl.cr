# Fixture for the FreeBSD::Sandbox.define `tls_context` directive.
#
# Declares `tls_context` (alongside `tz_data`, exercised together the same
# way the real appburg-id sandbox uses both), then — fully sandboxed
# (capability mode) — builds an HTTP::Client via `Sandbox.http_client_builder`
# and connects it to the driving spec's local plaintext HTTP echo server.
#
# This isn't a TLS handshake test (that's OpenSSL's own correctness, not this
# directive's) — it proves the two things that are actually this directive's
# job: (1) `Sandbox.tls_context`/`.http_client_builder` are usable at all
# post-cap_enter (accessing an unset class var, or one set too late, raises),
# and (2) an `HTTP::Client` built from that builder still works as a normal
# HTTP::Client under capability mode (connects, sends, reads a response) —
# i.e. building the client after cap_enter, via a context primed before it,
# doesn't itself break anything the sandbox would otherwise block.
#
# No privilege drop, so the fixture runs without root.
#
# Env vars set by the driving spec:
#   UPSTREAM_HOST, UPSTREAM_PORT — the local plaintext echo server to call

require "http/client"

require "../../../src/freebsd/sandbox"
require "../../../src/freebsd/casper/net"
require "../../../src/freebsd/casper/integrate/net"
require "../../../src/freebsd/casper/integrate/dns"

UPSTREAM_HOST = ENV["UPSTREAM_HOST"]
UPSTREAM_PORT = ENV["UPSTREAM_PORT"].to_i

FreeBSD::Sandbox.define do
  connect_dns({UPSTREAM_HOST => UPSTREAM_PORT})
  tz_data
  tls_context
end

# ---- sandboxed body ----

context = FreeBSD::Sandbox.tls_context
STDOUT.puts(context.is_a?(OpenSSL::SSL::Context::Client) ? "context-ok" : "context-ERROR")

builder = FreeBSD::Sandbox.http_client_builder(timeout: 5.seconds)
client = builder.call(URI.parse("http://#{UPSTREAM_HOST}:#{UPSTREAM_PORT}"), 5.seconds)
STDOUT.puts(client.is_a?(HTTP::Client) ? "builder-ok" : "builder-ERROR")

response = client.get("/")
STDOUT.puts "status #{response.status_code}"
STDOUT.puts "body #{response.body}"

STDOUT.puts "done"
STDOUT.flush
