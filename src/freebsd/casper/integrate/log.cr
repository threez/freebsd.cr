# Bridge from Crystal's `Log` framework to Casper's `system.syslog` service.
#
# `require "freebsd/casper/integrate/log"` adds `Casper::Log::SyslogBackend`, a
# `Log::Backend` that forwards each `Log::Entry` to the Casper helper as a
# `cap_syslog` call. Severities are mapped onto syslog priorities below.
#
# Usage:
#
# ```
# require "freebsd/casper"
# require "freebsd/casper/integrate/log"
#
# syslog = FreeBSD::Casper.install_syslog!(ident: "myapp")
# Log.setup(:info, FreeBSD::Casper::Log::SyslogBackend.new(syslog))
# FreeBSD::Capsicum.sandbox!
#
# Log.info { "running sandboxed" } # routed through cap_syslog
# ```
#
# Unlike the DNS/file/net integrations this is not a monkey-patch — it
# defines a new backend you opt into via the standard `Log.setup` API.

require "../syslog"
require "log"

module FreeBSD::Casper::Log
  class SyslogBackend < ::Log::Backend
    def initialize(@service : FreeBSD::Casper::Service::Syslog,
                   *,
                   @formatter : ::Log::Formatter = DefaultFormatter,
                   dispatcher : ::Log::DispatchMode | ::Log::Dispatcher = ::Log::DispatchMode::Sync)
      super(dispatcher)
    end

    def write(entry : ::Log::Entry) : Nil
      priority = severity_to_priority(entry.severity)
      message = String.build { |io| @formatter.format(entry, io) }
      @service.syslog(priority, message)
    end

    # Map Crystal `Log::Severity` onto a syslog `Priority`.
    def self.severity_to_priority(severity : ::Log::Severity) : FreeBSD::Casper::Service::Syslog::Priority
      case severity
      in .trace?, .debug? then FreeBSD::Casper::Service::Syslog::Priority::Debug
      in .info?           then FreeBSD::Casper::Service::Syslog::Priority::Info
      in .notice?         then FreeBSD::Casper::Service::Syslog::Priority::Notice
      in .warn?           then FreeBSD::Casper::Service::Syslog::Priority::Warning
      in .error?          then FreeBSD::Casper::Service::Syslog::Priority::Err
      in .fatal?          then FreeBSD::Casper::Service::Syslog::Priority::Crit
      in .none?           then FreeBSD::Casper::Service::Syslog::Priority::Info
      end
    end

    private def severity_to_priority(severity : ::Log::Severity) : FreeBSD::Casper::Service::Syslog::Priority
      SyslogBackend.severity_to_priority(severity)
    end

    # Default single-line formatter — source, message, and exception summary.
    # syslogd adds its own timestamp + host + program prefix.
    DefaultFormatter = ::Log::Formatter.new do |entry, io|
      io << entry.source << ": " unless entry.source.empty?
      io << entry.message
      if ex = entry.exception
        io << " - " << ex.class.name
        if msg = ex.message
          io << ": " << msg
        end
      end
    end
  end
end
