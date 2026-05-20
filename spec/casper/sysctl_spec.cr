require "../spec_helper"
require "../../src/freebsd/casper/sysctl"

describe FreeBSD::Casper::Service::Sysctl do
  it_on_capsicum "reads kern.ostype as a string" do
    chan = FreeBSD::Casper::Channel.open
    begin
      sysctl = chan.sysctl
      sysctl.limit({"kern.ostype" => FreeBSD::Casper::Service::Sysctl::Mode::Read})
      value = sysctl.get_string("kern.ostype")
      {"FreeBSD", "DragonFly"}.includes?(value).should be_true
    ensure
      chan.close
    end
  end
end
