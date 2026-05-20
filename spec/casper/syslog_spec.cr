require "../spec_helper"
require "../../src/freebsd/casper/syslog"
require "../../src/freebsd/casper/integrate/log"

describe FreeBSD::Casper::Service::Syslog do
  it_on_capsicum "openlog + syslog round-trips from a sandbox" do
    in_sandbox_child do
      chan = FreeBSD::Casper::Channel.open
      svc = chan.syslog
      chan.close
      svc.openlog("casper-spec",
        FreeBSD::Casper::Service::Syslog::LogOption::Pid,
        FreeBSD::Casper::Service::Syslog::Facility::Local0)
      FreeBSD::Capsicum.sandbox!
      svc.syslog(FreeBSD::Casper::Service::Syslog::Priority::Info, "hello from casper spec")
      svc.closelog
    end
  end

  it_on_capsicum "Log::SyslogBackend emits entries via the helper" do
    in_sandbox_child do
      svc = FreeBSD::Casper.install_syslog!(ident: "casper-log-spec",
        facility: FreeBSD::Casper::Service::Syslog::Facility::Local0)
      Log.setup(:debug, FreeBSD::Casper::Log::SyslogBackend.new(svc))
      # Prime the timezone cache before entering cap mode: Log::Entry timestamps
      # call Time.local which lazily reads /etc/localtime — blocked in cap mode.
      Time.local
      FreeBSD::Capsicum.sandbox!
      Log.info { "via Log framework" }
    end
  end
end
