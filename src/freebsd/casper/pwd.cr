require "../casper"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_pwd")]
  lib LibCapPwd
    # struct passwd from <pwd.h>
    struct Passwd
      pw_name : LibC::Char*
      pw_passwd : LibC::Char*
      pw_uid : UInt32
      pw_gid : UInt32
      pw_change : Int64
      pw_class : LibC::Char*
      pw_gecos : LibC::Char*
      pw_dir : LibC::Char*
      pw_shell : LibC::Char*
      pw_expire : Int64
      pw_fields : Int32
    end

    fun cap_getpwnam(chan : LibCasper::CapChannel, name : LibC::Char*) : Passwd*
    fun cap_getpwuid(chan : LibCasper::CapChannel, uid : UInt32) : Passwd*

    fun cap_pwd_limit_cmds(chan : LibCasper::CapChannel, cmds : LibC::Char**, ncmds : LibC::SizeT) : Int32
    fun cap_pwd_limit_fields(chan : LibCasper::CapChannel, fields : LibC::Char**, nfields : LibC::SizeT) : Int32
    fun cap_pwd_limit_users(chan : LibCasper::CapChannel,
                            names : LibC::Char**, nnames : LibC::SizeT,
                            uids : UInt32*, nuids : LibC::SizeT) : Int32
  end
{% end %}

module FreeBSD::Casper
  class Service::Pwd < Service
    # A password entry from the user database. Mirrors `struct passwd` from `<pwd.h>`.
    record Passwd,
      name : String,
      uid : UInt32,
      gid : UInt32,
      gecos : String,
      dir : String,
      shell : String

    # Look up a user by name. Returns `nil` if not found.
    def getpwnam(name : String) : Passwd?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptr = LibCapPwd.cap_getpwnam(@handle, name)
        ptr.null? ? nil : to_passwd(ptr.value)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Look up a user by UID. Returns `nil` if not found.
    def getpwuid(uid : UInt32 | Int32) : Passwd?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptr = LibCapPwd.cap_getpwuid(@handle, uid.to_u32)
        ptr.null? ? nil : to_passwd(ptr.value)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict which calls are permitted ("getpwnam", "getpwuid", ...).
    def limit_cmds(*cmds : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptrs = cmds.map(&.to_unsafe).to_a
        ptr = ptrs.empty? ? Pointer(LibC::Char*).null : ptrs.to_unsafe
        if LibCapPwd.cap_pwd_limit_cmds(@handle, ptr, ptrs.size.to_u64) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_pwd_limit_cmds")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict which fields are returned ("pw_name", "pw_uid", ...).
    def limit_fields(*fields : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptrs = fields.map(&.to_unsafe).to_a
        ptr = ptrs.empty? ? Pointer(LibC::Char*).null : ptrs.to_unsafe
        if LibCapPwd.cap_pwd_limit_fields(@handle, ptr, ptrs.size.to_u64) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_pwd_limit_fields")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict to a given set of users (by name and/or uid).
    def limit_users(names : Enumerable(String) = [] of String,
                    uids : Enumerable(UInt32) = [] of UInt32) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        name_ptrs = names.map(&.to_unsafe).to_a
        uid_arr = uids.map(&.to_u32).to_a
        rc = LibCapPwd.cap_pwd_limit_users(@handle,
          name_ptrs.empty? ? Pointer(LibC::Char*).null : name_ptrs.to_unsafe,
          name_ptrs.size.to_u64,
          uid_arr.empty? ? Pointer(UInt32).null : uid_arr.to_unsafe,
          uid_arr.size.to_u64)
        if rc != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_pwd_limit_users")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      private def to_passwd(p : LibCapPwd::Passwd) : Passwd
        Passwd.new(
          name: String.new(p.pw_name),
          uid: p.pw_uid,
          gid: p.pw_gid,
          gecos: p.pw_gecos.null? ? "" : String.new(p.pw_gecos),
          dir: p.pw_dir.null? ? "" : String.new(p.pw_dir),
          shell: p.pw_shell.null? ? "" : String.new(p.pw_shell),
        )
      end
    {% end %}
  end

  class Channel
    # Open the `system.pwd` Casper service on this channel.
    def pwd : Service::Pwd
      Service::Pwd.new(service("system.pwd"))
    end
  end

  @@pwd : Service::Pwd? = nil

  # The globally-installed Casper Pwd service, if any.
  def self.pwd? : Service::Pwd?
    @@pwd
  end

  def self.install_pwd(service : Service::Pwd) : Service::Pwd
    @@pwd = service
  end

  # Open a Casper channel, take `system.pwd`, install it globally, and close
  # the channel. Returns the service. Call `#limit_users` / `#limit_fields`
  # / `#limit_cmds` on the returned service to narrow permissions before
  # `FreeBSD::Capsicum.sandbox!`.
  def self.install_pwd! : Service::Pwd
    chan = Channel.open
    svc = chan.pwd
    chan.close
    install_pwd(svc)
  end

  def self.uninstall_pwd : Nil
    @@pwd = nil
  end

  # Install the Casper `system.pwd` service, injecting a `Crystal.main_user_code`
  # override. The block receives the `Service::Pwd` instance for configuration
  # (e.g. `limit_users`, `limit_fields`, `limit_cmds`) before the runtime starts.
  #
  # ```crystal
  # FreeBSD::Casper.register_pwd do |pwd|
  #   pwd.limit_users(names: ["root", "nobody"])
  # end
  #
  # FreeBSD::Capsicum.sandbox!
  # FreeBSD::Casper.pwd?.try(&.getpwnam("root")).try(&.shell)  # => "/bin/sh"
  # ```
  macro register_pwd(&block)
    def Crystal.main_user_code(argc : Int32, argv : UInt8**)
      \{% if flag?(:freebsd) || flag?(:dragonfly) %}
        _chan = FreeBSD::Casper::Channel.open
        _pwd  = _chan.pwd
        {% if block %}
          {{block.args[0].id}} = _pwd
          {{block.body}}
        {% end %}
        _chan.close
        FreeBSD::Casper.install_pwd(_pwd)
      \{% end %}
      previous_def
    end
  end
end
