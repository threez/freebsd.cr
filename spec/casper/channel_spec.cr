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

  # libcasper's channel RPC does a synchronous blocking recv; the socket must be
  # blocking or `cap_getaddrinfo` etc. can surface EDEADLK. Crystal opens it
  # O_NONBLOCK by default, so Channel.open / #service must clear that.
  it_on_capsicum "forces the channel socket blocking (no O_NONBLOCK)" do
    chan = FreeBSD::Casper::Channel.open
    begin
      chan_fd = LibCasper.cap_sock(chan.to_unsafe)
      chan_fd.should be >= 0
      (LibC.fcntl(chan_fd, LibC::F_GETFL, 0) & LibC::O_NONBLOCK).should eq(0)

      net = chan.net
      svc_fd = LibCasper.cap_sock(net.to_unsafe)
      svc_fd.should be >= 0
      (LibC.fcntl(svc_fd, LibC::F_GETFL, 0) & LibC::O_NONBLOCK).should eq(0)
      net.close
    ensure
      chan.close
    end
  end
end
