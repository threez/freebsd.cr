require "../spec_helper"
require "../../src/freebsd/casper/net"

describe FreeBSD::Casper::Service::Net do
  it_on_capsicum "connects to localhost via the helper from a sandbox" do
    server = TCPServer.new("127.0.0.1", 0)
    addr = server.local_address

    # The child connects via the casper net service. TCP buffers the connection
    # in the kernel so we can accept *after* in_sandbox_child completes — no
    # before_wait needed (and before_wait would deadlock if the child fails
    # before connecting, leaving server.accept blocked forever).
    in_sandbox_child do
      server.close # child's inherited copy of the listening fd
      chan = FreeBSD::Casper::Channel.open
      net = chan.net
      chan.close

      net.limit(FreeBSD::Casper::Service::Net::Mode::Connect) do |builder|
        builder.allow_connect(addr)
      end

      FreeBSD::Capsicum.sandbox!

      sock = ::Socket.new(::Socket::Family::INET, ::Socket::Type::STREAM, ::Socket::Protocol::TCP)
      net.connect(sock, addr)
      sock.close
    end

    # At this point the child succeeded; the connection sits in the kernel
    # accept queue and server.accept returns immediately.
    conn = server.accept
    conn.close
    server.close
  end

  it_on_capsicum "refuses connects outside the limit set" do
    in_sandbox_child do
      chan = FreeBSD::Casper::Channel.open
      net = chan.net
      chan.close

      allowed = ::Socket::IPAddress.new("127.0.0.1", 65000)
      forbidden = ::Socket::IPAddress.new("127.0.0.1", 1)
      net.limit(FreeBSD::Casper::Service::Net::Mode::Connect) do |builder|
        builder.allow_connect(allowed)
      end

      FreeBSD::Capsicum.sandbox!

      sock = ::Socket.new(::Socket::Family::INET, ::Socket::Type::STREAM, ::Socket::Protocol::TCP)
      begin
        expect_raises(::Socket::ConnectError) { net.connect(sock, forbidden) }
      ensure
        sock.close
      end
    end
  end
end
