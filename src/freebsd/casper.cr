# Entry point for FreeBSD Capsicum + libcasper bindings.
#
# Loads capsicum (capability mode, fd rights, process descriptors) via
# `require "freebsd/capsicum"`, then adds the libcasper service channel
# and the Crystal-native Helper privsep framework.
#
# Individual services require explicit opt-in:
#
# ```
# require "freebsd/casper"
# require "freebsd/casper/dns"
#
# chan = FreeBSD::Casper::Channel.open # before sandboxing
# dns = chan.dns
# chan.close # parent handle no longer needed
#
# FreeBSD::Capsicum.sandbox do
#   # We are now in capability mode.
#   addrs = dns.getaddrinfo("example.com")
#   # File.open("/etc/passwd") would raise ECAPMODE here.
# end
# ```
require "./capsicum"

require "./casper/lib_casper"
require "./casper/link_pin"
require "./casper/channel"
require "./casper/service"
require "./casper/helper"
