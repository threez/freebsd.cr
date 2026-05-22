# Transparent DNS integration.
#
# `require "freebsd/casper/integrate/dns"` reopens `Crystal::System::Addrinfo` and
# replaces its low-level `getaddrinfo` handle producer. When a Casper Net
# service is installed via `Casper.install_net!`, every `Socket::Addrinfo`
# lookup — which includes `TCPSocket.new("host", port)`, URI host resolution,
# `HTTP::Client.get`, and friends — is silently routed through the Casper
# helper instead of `LibC.getaddrinfo`. With no Net service installed the
# original libc path is taken, so this require is safe to load unconditionally.
#
# Note: `system.net` (`cap_net(3)`) is the preferred service for all network
# operations including DNS. The older `system.dns` service is obsolete per
# FreeBSD man pages and is not supported by this library.
# Configure the service for DNS with `Mode::Name2Addr` and/or
# `Mode::ConnectDNS` limits via `Service::Net#limit`.

require "../net"
require "socket"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module Crystal::System::Addrinfo
    def self.getaddrinfo(domain, service, family, type, protocol, timeout, flags = 0) : Handle
      if net = FreeBSD::Casper.net?
        hints = LibC::Addrinfo.new
        hints.ai_family = (family || ::Socket::Family::UNSPEC).to_i32
        hints.ai_socktype = type.to_i32 if type
        hints.ai_protocol = protocol.to_i32 if protocol
        flags |= LibC::AI_NUMERICSERV if service.is_a?(Int)
        hints.ai_flags = flags

        FreeBSD::Capsicum.syscall do
          net.raw_getaddrinfo(domain, service.to_s, pointerof(hints))
        end
      else
        previous_def
      end
    end
  end
{% end %}
