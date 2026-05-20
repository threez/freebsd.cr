require "socket"

module FreeBSD::Audit
  # Builds tokens into an open audit record.
  #
  # Instances are yielded by `Event.write` and `Event.discard` — do not
  # construct directly.
  #
  # Conventional token order in a BSM record:
  # 1. `subject` (who)
  # 2. `text` (what)
  # 3. `address` (from where)
  # 4. `return_success` / `return_failure` (outcome)
  class Record
    # Number of token write failures accumulated during this record.
    # Non-zero only when `strict: false` (the default).
    getter write_failures : Int32 = 0

    # Called only by `Event` — not part of the public API.
    protected def initialize(@descriptor : Int32, @strict : Bool)
    end

    # Append a plain-text token to the record.
    def text(message : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        write_token LibBsm.au_to_text(message)
      {% end %}
    end

    # Append a subject token describing the process writing the record.
    #
    # Defaults to the current effective UID/GID and PID. Pass *terminal* as
    # a dotted-decimal IPv4 string or colon-separated IPv6 string to populate
    # the terminal-address field; omit it (or pass `nil`) for daemon processes.
    def subject(uid : UInt32 = LibBsm.geteuid.to_u32,
                pid : Int32 = Process.pid.to_i32,
                session : UInt32 = 0_u32,
                terminal : String? = nil) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        auid = LibBsm::AU_NOAUDITID
        egid = LibBsm.getegid.to_u32
        rgid = LibBsm.getgid.to_u32
        ruid = LibC.getuid.to_u32

        if term = terminal
          if term.includes?(':')
            write_token subject32_ex(auid, uid, egid, ruid, rgid, pid, session, term)
          else
            write_token subject32_ipv4(auid, uid, egid, ruid, rgid, pid, session, term)
          end
        else
          write_token subject32_no_terminal(auid, uid, egid, ruid, rgid, pid, session)
        end
      {% end %}
    end

    # Append a remote-address token for the peer that triggered the event.
    #
    # Accepts dotted-decimal IPv4 (e.g. `"192.168.1.1"`) or colon-separated
    # IPv6 (e.g. `"::1"`). Raises `InvalidArgumentError` if the string cannot
    # be parsed by `inet_pton(3)`.
    def address(addr : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        if addr.includes?(':')
          in6 = LibC::In6Addr.new
          result = LibBsm.inet_pton(Socket::Family::INET6.value, addr, pointerof(in6).as(Void*))
          raise InvalidArgumentError.new("inet_pton: invalid IPv6 address #{addr.inspect}") if result != 1
          write_token LibBsm.au_to_in_addr_ex(pointerof(in6))
        else
          in4 = LibC::InAddr.new
          result = LibBsm.inet_pton(Socket::Family::INET.value, addr, pointerof(in4).as(Void*))
          raise InvalidArgumentError.new("inet_pton: invalid IPv4 address #{addr.inspect}") if result != 1
          write_token LibBsm.au_to_in_addr(pointerof(in4))
        end
      {% end %}
    end

    # Append an OCSF activity_id token as a text token.
    #
    # Format: `activity_id=N activity=Name`
    #
    # This is called automatically by `Event.write_activity` — you rarely need
    # to call it directly.
    def activity_id(id : UInt8, name : String) : Nil
      text("activity_id=#{id} activity=#{name}")
    end

    # Append a return token indicating success.
    def return_success(ret : UInt32 = 0_u32) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        write_token LibBsm.au_to_return32(0_u8, ret)
      {% end %}
    end

    # Append a return token indicating failure. *errno* is the error code
    # (e.g. `Errno::EACCES.value.to_u32`).
    def return_failure(errno : UInt32 = 0_u32) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        write_token LibBsm.au_to_return32(1_u8, errno)
      {% end %}
    end

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    private def subject32_no_terminal(auid, uid, egid, ruid, rgid, pid, session) : LibBsm::AuToken
      tid = LibBsm::AuTid.new(port: 0_u32, machine: 0_u32)
      LibBsm.au_to_subject32(auid, uid, egid, ruid, rgid, pid, session, pointerof(tid))
    end

    private def subject32_ipv4(auid, uid, egid, ruid, rgid, pid, session, term : String) : LibBsm::AuToken
      in_addr = LibC::InAddr.new
      result = LibBsm.inet_pton(Socket::Family::INET.value, term, pointerof(in_addr).as(Void*))
      raise InvalidArgumentError.new("inet_pton: invalid IPv4 address #{term.inspect}") if result != 1
      tid = LibBsm::AuTid.new(port: 0_u32, machine: in_addr.s_addr)
      LibBsm.au_to_subject32(auid, uid, egid, ruid, rgid, pid, session, pointerof(tid))
    end

    private def subject32_ex(auid, uid, egid, ruid, rgid, pid, session, term : String) : LibBsm::AuToken
      tid = LibBsm::AuTidAddr.new(at_port: 0_u32, at_type: 16_u32)
      result = LibBsm.inet_pton(Socket::Family::INET6.value, term, tid.at_addr.to_unsafe.as(Void*))
      raise InvalidArgumentError.new("inet_pton: invalid IPv6 address #{term.inspect}") if result != 1
      LibBsm.au_to_subject32_ex(auid, uid, egid, ruid, rgid, pid, session, pointerof(tid))
    end

    # Write *tok* into the record.
    #
    # On success `au_write` takes ownership — do not free.
    # On failure the token is untouched — free it and optionally raise.
    private def write_token(tok : LibBsm::AuToken) : Nil
      if LibBsm.au_write(@descriptor, tok) == -1
        LibBsm.au_free_token(tok)
        @write_failures += 1
        raise TokenWriteError.from_errno("au_write") if @strict
      end
    end
  end
end
