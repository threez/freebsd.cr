# Logging to syslog from a Capsicum sandbox via register_syslog.
#
# register_syslog injects a Crystal.main_user_code override that opens the
# Casper channel, calls openlog, and installs the system.syslog service before
# the Crystal runtime starts. The integrate/log backend is included automatically.
# The program body wires up Crystal's Log framework and calls sandbox!.

require "log"

require "../src/freebsd/casper"
require "../src/freebsd/casper/syslog"

FreeBSD::Casper.register_syslog(
  ident: "casper-syslog-example",
  options: FreeBSD::Casper::Service::Syslog::LogOption::Pid,
  facility: FreeBSD::Casper::Service::Syslog::Facility::User,
)

Time::Location.local # prime timezone cache before sandboxing

FreeBSD::Capsicum.sandbox!

syslog = FreeBSD::Casper.syslog?.not_nil!
Log.setup(:debug, FreeBSD::Casper::Log::SyslogBackend.new(syslog))

Log.info  { "sandboxed — this message goes to syslog" }
Log.warn  { "something worth noting" }
Log.error { "something went wrong" }

puts "Messages sent to syslog (check: sudo tail -f /var/log/messages)"
