require "../spec_helper"
require "../../src/freebsd/casper/pwd"

describe FreeBSD::Casper::Service::Pwd do
  it_on_capsicum "looks up root by name" do
    chan = FreeBSD::Casper::Channel.open
    begin
      pwd = chan.pwd
      entry = pwd.getpwnam("root")
      entry.should be_a(FreeBSD::Casper::Service::Pwd::Passwd)
      entry.try(&.uid).should eq(0)
    ensure
      chan.close
    end
  end

  it_on_capsicum "looks up uid 0" do
    chan = FreeBSD::Casper::Channel.open
    begin
      entry = chan.pwd.getpwuid(0_u32)
      entry.should be_a(FreeBSD::Casper::Service::Pwd::Passwd)
      entry.try(&.name).should eq("root")
    ensure
      chan.close
    end
  end
end
