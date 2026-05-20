require "../spec_helper"
require "../../src/freebsd/casper/dns"

describe FreeBSD::Casper::Channel do
  it_on_capsicum "opens and closes a channel to casperd" do
    chan = FreeBSD::Casper::Channel.open
    chan.closed?.should be_false
    chan.close
    chan.closed?.should be_true
  end

  it_on_capsicum "opens the system.dns service" do
    chan = FreeBSD::Casper::Channel.open
    begin
      dns = chan.dns
      dns.should be_a(FreeBSD::Casper::Service::DNS)
      dns.close
    ensure
      chan.close
    end
  end
end
