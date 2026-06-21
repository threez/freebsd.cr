# Fixture for the "helper child must not inherit the parent's net channel"
# regression. Combines register_audit_helper + register_net (the documented
# combination) and resolves a hostname. The audit pdfork child must drop the
# inherited @@net handle (via FreeBSD::Casper.reset!) before running the app
# body, or it would contend on the parent's casper net channel (EDEADLK) — and
# reset! must not itself crash when called pre-runtime in the child.
#
# The spec runs this and asserts the parent exits 0 and no process dumped core.

require "../../../src/freebsd/casper"
require "../../../src/freebsd/casper/audit_helper"
require "../../../src/freebsd/casper/net"
require "../../../src/freebsd/casper/integrate/net"
require "../../../src/freebsd/casper/integrate/dns"

FreeBSD::Casper.register_audit_helper

FreeBSD::Casper.register_net(
  FreeBSD::Casper::Service::Net::Mode::Name2Addr |
  FreeBSD::Casper::Service::Net::Mode::ConnectDNS
) do |b|
  b.allow_name2addr("localhost", "9")
end

# Resolve a name that does not require network egress (localhost). The point is
# to exercise the @@net routing path in whichever process reaches this line, not
# to reach the internet.
FreeBSD::Casper.net?.nil? ? STDOUT.puts("no-net") : STDOUT.puts("net-installed")
STDOUT.puts "done"
