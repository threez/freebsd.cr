# Fixture for the FreeBSD::Sandbox.define compose regression.
#
# One declaration combines a pre-runtime pdfork helper (audit_helper), a
# `connect_dns` net policy, an `open` resource opened before the sandbox,
# a privileged `bind` listener, and the final cap_enter. The helper child must
# traverse NONE of the post-runtime setup (services / opens / binds / cap_enter)
# — that is exactly what the single `unless Helper.is_helper` guard in `define`
# protects, and what an earlier hand-wired arrangement got wrong (cap_init in
# the child → EDEADLK).
#
# This also exercises cap_rights_limit on the carried fds:
#   * `open("ro", File, rights: [:read, :fstat])` — read works, write rejected.
#   * `bind "lis", ... (default rights)` — accept works inside the sandbox.
#
# No privilege drop here so the fixture runs without root. The driving spec
# reads the listener address from stdout, connects from the (unsandboxed) spec
# process, and the fixture accepts the connection inside capability mode.

require "../../../src/freebsd/sandbox"
require "../../../src/freebsd/casper/audit_helper"
require "../../../src/freebsd/casper/net"

FreeBSD::Sandbox.define do
  audit_helper

  connect_dns "localhost", 9

  open("ro", File, rights: [:read, :fstat]) { File.open("/etc/hosts", "r") }
  bind "lis", "127.0.0.1", 0
end

# ---- sandboxed body ----

FreeBSD::Casper.net?.nil? ? STDOUT.puts("no-net") : STDOUT.puts("net-installed")

# Read-only opened file: read works, write is rejected by the applied rights.
ro = FreeBSD::Sandbox.ro
STDOUT.puts(ro.gets.nil? ? "ro-empty" : "ro-readable")
begin
  ro.print("x")
  ro.flush
  STDOUT.puts "ro-write-ERROR-allowed"
rescue ex
  STDOUT.puts "ro-write-blocked"
end

# Direct file access is blocked by capability mode.
begin
  File.open("/etc/passwd", "r", &.gets)
  STDOUT.puts "passwd-open-ERROR"
rescue File::Error
  STDOUT.puts "passwd-blocked"
end

# Announce the listener address so the spec process can connect to it, then
# accept inside the sandbox — proving the default listener rights permit accept.
lis = FreeBSD::Sandbox.lis
addr = lis.local_address
STDOUT.puts "listen #{addr.address} #{addr.port}"
STDOUT.flush

conn = lis.accept
STDOUT.puts "accept-ok"
conn.close

STDOUT.puts "done"
STDOUT.flush
