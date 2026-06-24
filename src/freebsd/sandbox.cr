# Entry point for `FreeBSD::Sandbox` — a single declarative description of a
# sandboxed process: which user it runs as (privilege drop), which Casper
# resources it uses (net, audit, pwd, …), which ports it binds, and which
# arbitrary resources it opens up-front (e.g. a database file) for use once
# sandboxed.
#
# It composes the lower-level building blocks (`FreeBSD::Privdrop`,
# `FreeBSD::Capsicum`, `FreeBSD::Casper`) and runs them in the one mandatory
# order, so callers don't have to memorise the pre-runtime / post-runtime /
# privdrop / `cap_enter` sequence or wire up the helper-child guards by hand.
#
# ```
# require "freebsd/sandbox"
# require "freebsd/casper/net"
#
# FreeBSD::Sandbox.define do
#   user "nobody", chroot: "/var/empty"
#
#   audit_helper # pre-runtime pdfork helper
#
#   net(FreeBSD::Casper::Service::Net::Mode::Name2Addr |
#       FreeBSD::Casper::Service::Net::Mode::ConnectDNS) do |b|
#     b.allow_name2addr("example.com", "80")
#   end
#
#   open("db") { File.open("/var/db/app.sqlite", "r+") }
#   bind "listener", "0.0.0.0", 8080
# end
#
# # ---- program body runs here, fully sandboxed ----
# # Each open/bind directive generates a typed accessor named after it:
# db = FreeBSD::Sandbox.db             # => File
# listener = FreeBSD::Sandbox.listener # => TCPServer
# ```
module FreeBSD::Sandbox
  # True when running on a platform that supports the sandbox primitives
  # (FreeBSD or DragonFlyBSD).
  SUPPORTED = {{ flag?(:freebsd) || flag?(:dragonfly) }}
end

require "./privdrop"
require "./capsicum"
require "./casper"

require "./sandbox/builder"
require "./sandbox/define"
