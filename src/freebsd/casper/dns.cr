require "../casper"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_dns")]
  lib LibCapDns
    # struct addrinfo and hostent come from libc; we only need pointers here.
    fun cap_getaddrinfo(chan : LibCasper::CapChannel,
                        hostname : LibC::Char*,
                        servname : LibC::Char*,
                        hints : Void*,
                        res : Void**) : Int32

    fun cap_getnameinfo(chan : LibCasper::CapChannel,
                        sa : Void*, salen : LibC::SocklenT,
                        host : LibC::Char*, hostlen : LibC::SocklenT,
                        serv : LibC::Char*, servlen : LibC::SocklenT,
                        flags : Int32) : Int32

    fun cap_gethostbyname(chan : LibCasper::CapChannel, name : LibC::Char*) : Void*
    fun cap_gethostbyname2(chan : LibCasper::CapChannel, name : LibC::Char*, af : Int32) : Void*
    fun cap_gethostbyaddr(chan : LibCasper::CapChannel, addr : Void*, len : LibC::SocklenT, af : Int32) : Void*

    fun cap_dns_type_limit(chan : LibCasper::CapChannel, types : LibC::Char**, ntypes : LibC::SizeT) : Int32
    fun cap_dns_family_limit(chan : LibCasper::CapChannel, families : Int32*, nfamilies : LibC::SizeT) : Int32
  end
{% end %}

require "socket"

module FreeBSD::Casper
  class Service::DNS < Service
    # A single resolved address entry returned by `#getaddrinfo`. Mirrors
    # the fields of `LibC::Addrinfo` in Crystal-native types.
    record Addrinfo,
      family : ::Socket::Family,
      type : ::Socket::Type,
      protocol : ::Socket::Protocol,
      canonname : String?,
      address : ::Socket::IPAddress

    # Resolve `host` (and optional `service`) via the Casper DNS helper.
    # Returns one entry per result.
    def getaddrinfo(host : String, service : String? = nil) : Array(Addrinfo)
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptr = raw_getaddrinfo(host, service, Pointer(LibC::Addrinfo).null)
        begin
          parse_addrinfo_chain(ptr)
        ensure
          LibC.freeaddrinfo(ptr) unless ptr.null?
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Low-level: perform `cap_getaddrinfo` and return the raw `LibC::Addrinfo*`
    # chain. The caller owns the chain and must release it with
    # `LibC.freeaddrinfo`. Used by the `casper/integrate/dns` integration to
    # hand the chain directly to Crystal's `Socket::Addrinfo`.
    #
    # Raises `Socket::Addrinfo::Error` on resolution failure, mirroring
    # Crystal's stdlib error semantics.
    def raw_getaddrinfo(host : String,
                        service : String? = nil,
                        hints : LibC::Addrinfo* = Pointer(LibC::Addrinfo).null) : LibC::Addrinfo*
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        res = Pointer(LibC::Addrinfo).null
        svc = service.nil? ? Pointer(LibC::Char).null : service.to_unsafe
        rc = LibCapDns.cap_getaddrinfo(@handle, host, svc,
          hints.as(Void*), pointerof(res).as(Void**))
        unless rc.zero?
          raise ::Socket::Addrinfo::Error.from_os_error(nil, Errno.new(rc), domain: host)
        end
        res
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Reverse DNS for `addr`.
    def getnameinfo(addr : ::Socket::IPAddress, flags : Int32 = 0) : {String, String}
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        host = Bytes.new(1025)
        serv = Bytes.new(32)
        sa = addr.to_unsafe
        salen = addr.size
        rc = LibCapDns.cap_getnameinfo(@handle,
          sa.as(Void*), salen,
          host.to_unsafe.as(LibC::Char*), host.size.to_u32,
          serv.to_unsafe.as(LibC::Char*), serv.size.to_u32,
          flags)
        unless rc.zero?
          raise ::Socket::Addrinfo::Error.from_os_error(nil, Errno.new(rc), domain: addr.address)
        end
        {String.new(host.to_unsafe), String.new(serv.to_unsafe)}
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict which DNS query types the helper will perform.
    # Valid `types` include "ADDR", "ADDR2NAME", "NAME", "NAME2ADDR".
    def limit_types(*types : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptrs = types.map { |t| t.to_unsafe }.to_a
        if LibCapDns.cap_dns_type_limit(@handle, ptrs.to_unsafe, ptrs.size.to_u64) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_dns_type_limit")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict allowed address families (e.g. AF_INET, AF_INET6).
    def limit_families(*families : ::Socket::Family) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        arr = families.map(&.value.to_i32).to_a
        if LibCapDns.cap_dns_family_limit(@handle, arr.to_unsafe, arr.size.to_u64) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_dns_family_limit")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      private def parse_addrinfo_chain(head : LibC::Addrinfo*) : Array(Addrinfo)
        results = [] of Addrinfo
        cursor = head
        while !cursor.null?
          ai = cursor.value
          cursor = ai.ai_next
          # Skip entries with families Crystal doesn't enumerate. Type and
          # protocol fall back to STREAM/IP for unknown values (e.g. SCTP =
          # 132 isn't in `Socket::Protocol`).
          family = ::Socket::Family.from_value?(ai.ai_family)
          next unless family
          type = ::Socket::Type.from_value?(ai.ai_socktype) || ::Socket::Type::STREAM
          proto = ::Socket::Protocol.from_value?(ai.ai_protocol) || ::Socket::Protocol::IP
          canon = ai.ai_canonname.null? ? nil : String.new(ai.ai_canonname)
          addr = ::Socket::IPAddress.from(ai.ai_addr.as(LibC::Sockaddr*), ai.ai_addrlen)
          results << Addrinfo.new(family, type, proto, canon, addr)
        end
        results
      end
    {% end %}
  end

  class Channel
    # Open the `system.dns` Casper service on this channel.
    def dns : Service::DNS
      Service::DNS.new(service("system.dns"))
    end
  end

  @@dns : Service::DNS? = nil

  # The globally-installed Casper DNS service, if any. When set, the
  # `casper/integrate/dns` integration routes Crystal's `Socket::Addrinfo`
  # resolutions (and therefore `TCPSocket.new("host", port)`, `URI` lookups,
  # `HTTP::Client.get`, …) through this helper instead of `LibC.getaddrinfo`.
  def self.dns? : Service::DNS?
    @@dns
  end

  # Register `service` as the process-wide DNS resolver. The caller keeps
  # ownership; closing it withdraws the integration.
  def self.install_dns(service : Service::DNS) : Service::DNS
    @@dns = service
  end

  # Open a fresh Casper channel, take its `system.dns` service, close the
  # channel, and install the service globally. Convenience for the common
  # "set up DNS, then sandbox" flow.
  def self.install_dns! : Service::DNS
    chan = Channel.open
    dns = chan.dns
    chan.close
    install_dns(dns)
  end

  # Forget the globally-installed DNS service. Subsequent name resolutions
  # fall back to `LibC.getaddrinfo`.
  def self.uninstall_dns : Nil
    @@dns = nil
  end
end
