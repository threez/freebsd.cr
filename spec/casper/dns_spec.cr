require "../spec_helper"
require "../../src/freebsd/casper/dns"

describe FreeBSD::Casper::Service::DNS do
  it_on_capsicum "resolves localhost via the helper" do
    chan = FreeBSD::Casper::Channel.open
    begin
      dns = chan.dns
      addrs = dns.getaddrinfo("localhost")
      addrs.should_not be_empty
      addrs.first.address.address.should match(/^(127\.|::1)/)
    ensure
      chan.close
    end
  end

  it_on_capsicum "works after entering capability mode" do
    in_sandbox_child do
      chan = FreeBSD::Casper::Channel.open
      dns = chan.dns
      chan.close
      FreeBSD::Capsicum.sandbox!
      dns.getaddrinfo("localhost").should_not be_empty
    end
  end
end
