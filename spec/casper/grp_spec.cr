require "../spec_helper"
require "../../src/freebsd/casper/grp"

describe FreeBSD::Casper::Service::Grp do
  it_on_capsicum "looks up wheel by name" do
    chan = FreeBSD::Casper::Channel.open
    begin
      entry = chan.grp.getgrnam("wheel")
      entry.should be_a(FreeBSD::Casper::Service::Grp::Group)
      entry.try(&.gid).should eq(0)
    ensure
      chan.close
    end
  end
end
