# Transparent DNS integration.
#
# `require "freebsd/casper/integrate/dns"` reopens `Crystal::System::Addrinfo` and
# replaces its low-level `getaddrinfo` handle producer. When a Casper DNS
# service is installed via `Casper.install_dns!`, every `Socket::Addrinfo`
# lookup — which includes `TCPSocket.new("host", port)`, `URI.parse(...).host`
# resolution, `HTTP::Client.get`, and friends — is silently routed through the
# Casper helper instead of `LibC.getaddrinfo`. With no DNS installed the
# original libc path is taken, so this require is safe to load unconditionally.

require "../dns"
require "socket"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module Crystal::System::Addrinfo
    def self.getaddrinfo(domain, service, family, type, protocol, timeout, flags = 0) : Handle
      if dns = FreeBSD::Casper.dns?
        hints = LibC::Addrinfo.new
        hints.ai_family = (family || ::Socket::Family::UNSPEC).to_i32
        hints.ai_socktype = type.to_i32 if type
        hints.ai_protocol = protocol.to_i32 if protocol
        flags |= LibC::AI_NUMERICSERV if service.is_a?(Int)
        hints.ai_flags = flags

        FreeBSD::Capsicum.syscall do
          dns.raw_getaddrinfo(domain, service.to_s, pointerof(hints))
        end
      else
        previous_def
      end
    end
  end
{% end %}
