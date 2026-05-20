# Transparent `Socket` bind/connect integration.
#
# `require "freebsd/casper/integrate/net"` reopens `Crystal::System::Socket` and
# routes its `system_bind` and `system_connect` chokepoints through the
# Casper Net helper when one is installed via `Casper.install_net!`. With no
# Net service installed, the ordinary `LibC.bind`/`LibC.connect` paths are
# taken, so this require is safe to load unconditionally.
#
# Why this exists — on FreeBSD plain `bind`/`connect` work in capability
# mode, so this integration is *policy enforcement* (via `cap_net_limit_*`),
# not "make stdlib work in a sandbox". Install Net, configure limits, then
# use `TCPSocket.new(...)` / `UDPSocket#bind` as normal — the helper rejects
# operations outside the policy with `Socket::ConnectError` /
# `Socket::BindError`.
#
# Caveats:
#
# * `cap_connect` is a synchronous policy check + `connect(2)`. The override
#   does not consult Crystal's event loop, so `Socket#connect(timeout:)`
#   semantics are coarsened: the call blocks (cooperatively via
#   `Fiber.syscall`) until the connect completes or the kernel times it out
#   on its own. For latency-sensitive code, prefer pre-connecting before
#   sandboxing.
# * Only TCP/UDP-style address-bearing operations are intercepted.
#   `listen`/`accept`/`send`/`recv` keep their stdlib paths.

require "../net"
require "socket"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module Crystal::System::Socket
    private def system_bind(addr, addrstr)
      if net = FreeBSD::Casper.net?
        begin
          net.bind_raw(fd, addr.to_unsafe, addr.size.to_u32)
          nil
        rescue ex : ::Socket::BindError
          ex
        end
      else
        previous_def
      end
    end

    private def system_connect(addr, timeout = nil)
      if net = FreeBSD::Casper.net?
        begin
          FreeBSD::Capsicum.syscall { net.connect_raw(fd, addr.to_unsafe, addr.size.to_u32) }
          nil
        rescue ex : ::Socket::ConnectError
          ex
        end
      else
        previous_def
      end
    end
  end
{% end %}
