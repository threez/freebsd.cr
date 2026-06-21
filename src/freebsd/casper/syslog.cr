require "../casper"
require "./integrate/log"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_syslog")]
  lib LibCapSyslog
    fun cap_openlog(chan : LibCasper::CapChannel,
                    ident : LibC::Char*,
                    logopt : Int32,
                    facility : Int32) : Void

    # The C signature is variadic (`printf`-style). We declare a fixed-arg
    # form because Crystal's variadic-call machinery (at least through 1.19)
    # demands `to_unsafe` on every argument including the pre-`...` fixed
    # ones, which a raw `Pointer(Void)` doesn't have. Always calling with
    # `"%s"` + one C string keeps the ABI compatible on amd64 (the only
    # platform where libcasper currently runs) and side-steps any
    # printf-format injection from the message body.
    fun cap_syslog(chan : LibCasper::CapChannel, priority : Int32, fmt : LibC::Char*, arg : LibC::Char*) : Void

    fun cap_closelog(chan : LibCasper::CapChannel) : Void
    fun cap_setlogmask(chan : LibCasper::CapChannel, mask : Int32) : Int32
  end
{% end %}

module FreeBSD::Casper
  # Casper's `system.syslog` service: write to `syslogd(8)` from inside a
  # capability-mode process where direct socket access to `/var/run/log`
  # would be unavailable. Mirrors `syslog(3)` in shape — `openlog` ⇒
  # `syslog` ⇒ `closelog`.
  #
  # See `casper/integrate/log` for a Crystal `Log::Backend` adaptor that
  # wires Crystal's `Log` framework on top of this service.
  class Service::Syslog < Service
    # Standard syslog priority levels (matches `<syslog.h>`).
    enum Priority : Int32
      Emerg   = 0
      Alert   = 1
      Crit    = 2
      Err     = 3
      Warning = 4
      Notice  = 5
      Info    = 6
      Debug   = 7
    end

    # Standard syslog facilities (matches `<syslog.h>` — `(N << 3)`).
    enum Facility : Int32
      Kern     = 0 << 3
      User     = 1 << 3
      Mail     = 2 << 3
      Daemon   = 3 << 3
      Auth     = 4 << 3
      Syslog   = 5 << 3
      Lpr      = 6 << 3
      News     = 7 << 3
      Uucp     = 8 << 3
      Cron     = 9 << 3
      AuthPriv = 10 << 3
      Ftp      = 11 << 3
      Local0   = 16 << 3
      Local1   = 17 << 3
      Local2   = 18 << 3
      Local3   = 19 << 3
      Local4   = 20 << 3
      Local5   = 21 << 3
      Local6   = 22 << 3
      Local7   = 23 << 3
    end

    # `openlog(3)` option flags.
    @[Flags]
    enum LogOption : Int32
      Pid    = 0x01
      Cons   = 0x02
      Odelay = 0x04
      Ndelay = 0x08
      Nowait = 0x10
      Perror = 0x20
    end

    # Set the identifier, options, and default facility — same as `openlog(3)`.
    # Subsequent `#syslog` calls without an explicit facility use this one.
    def openlog(ident : String,
                options : LogOption = LogOption::None,
                facility : Facility = Facility::User) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        LibCapSyslog.cap_openlog(@handle, ident, options.value, facility.value)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Emit `message` at the given `priority` (and optional override `facility`).
    def syslog(priority : Priority, message : String, facility : Facility? = nil) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        prio = priority.value
        prio |= facility.value if facility
        # See lib_cap_syslog.cr for why this is called with a fixed-arg
        # signature even though the C function is variadic.
        LibCapSyslog.cap_syslog(@handle, prio, "%s", message.to_unsafe)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict which priorities are delivered. Matches `setlogmask(3)`; the
    # mask is a bitwise OR of `(1 << priority.value)` for each priority that
    # should be enabled. Returns the previous mask.
    def log_mask=(mask : Int32) : Int32
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        LibCapSyslog.cap_setlogmask(@handle, mask)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Convenience: enable every priority up to and including `priority`.
    def log_up_to(priority : Priority) : Int32
      self.log_mask = (1 << (priority.value + 1)) - 1
    end

    # Close the identifier on the helper side. The service handle itself
    # stays usable until `#close` is called.
    def closelog : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        LibCapSyslog.cap_closelog(@handle)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end
  end

  class Channel
    # Open the `system.syslog` Casper service on this channel.
    def syslog : Service::Syslog
      Service::Syslog.new(service("system.syslog"))
    end
  end

  @@syslog : Service::Syslog? = nil

  # The globally-installed Casper Syslog service, if any. Used by the
  # `casper/integrate/log` backend.
  def self.syslog? : Service::Syslog?
    @@syslog
  end

  def self.install_syslog(service : Service::Syslog) : Service::Syslog
    @@syslog = service
  end

  # Open a Casper channel, take `system.syslog`, call `openlog` with the
  # given identifier, install the service globally, and close the channel.
  def self.install_syslog!(ident : String,
                           options : Service::Syslog::LogOption = Service::Syslog::LogOption::None,
                           facility : Service::Syslog::Facility = Service::Syslog::Facility::User) : Service::Syslog
    chan = Channel.open
    svc = chan.syslog
    chan.close
    svc.openlog(ident, options, facility)
    install_syslog(svc)
  end

  def self.uninstall_syslog : Nil
    @@syslog = nil
  end

  # Install the Casper `system.syslog` service, injecting a `Crystal.main_user_code`
  # override. Arguments mirror `install_syslog!`.
  #
  # ```
  # require "freebsd/casper/syslog"
  # require "freebsd/casper/integrate/log"
  #
  # FreeBSD::Casper.register_syslog(
  #   ident: "myapp",
  #   options: FreeBSD::Casper::Service::Syslog::LogOption::Pid,
  #   facility: FreeBSD::Casper::Service::Syslog::Facility::Local0,
  # )
  #
  # FreeBSD::Capsicum.sandbox!
  # Log.setup(:info, FreeBSD::Casper::Log::SyslogBackend.new(FreeBSD::Casper.syslog!))
  # Log.info { "ready" }
  # ```
  macro register_syslog(ident, options = FreeBSD::Casper::Service::Syslog::LogOption::None, facility = FreeBSD::Casper::Service::Syslog::Facility::User)
    def Crystal.main_user_code(argc : Int32, argv : UInt8**)
      \{% if flag?(:freebsd) || flag?(:dragonfly) %}
        FreeBSD::Casper.install_syslog!({{ident}}, {{options}}, {{facility}}) unless FreeBSD::Casper::Helper.is_helper
      \{% end %}
      previous_def
    end
  end
end
