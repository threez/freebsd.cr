require "../spec_helper"
require "../../src/freebsd/casper/net"

describe FreeBSD::Casper::Channel do
  it_on_capsicum "opens and closes a channel to casperd" do
    chan = FreeBSD::Casper::Channel.open
    chan.closed?.should be_false
    chan.close
    chan.closed?.should be_true
  end

  it_on_capsicum "opens the system.net service" do
    chan = FreeBSD::Casper::Channel.open
    begin
      net = chan.net
      net.should be_a(FreeBSD::Casper::Service::Net)
      net.close
    ensure
      chan.close
    end
  end
end
