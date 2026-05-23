require "../casper"
require "../audit"
require "../audit/record_builder"
require "./codec/nvlist"

module FreeBSD::Casper
  # Capsicum-safe BSM audit writes via a privileged privsep helper.
  #
  # `au_open(3)` / `au_write(3)` require kernel audit facilities unavailable
  # inside a Capsicum sandbox. This module forks a helper process *before*
  # `cap_enter()` that holds the audit pipe and serves NVList-encoded write
  # requests from the sandboxed parent.
  #
  # ## Usage
  #
  # ```crystal
  # require "freebsd/casper/audit_helper"
  #
  # FreeBSD::Casper.register_audit_helper   # top-level — forks helper pre-sandbox
  #
  # FreeBSD::Capsicum.sandbox!
  #
  # FreeBSD::Casper::AuditHelper::Event.write(FreeBSD::Audit::AUE::Authentication) do |r|
  #   r.subject uid: LibC.getuid.to_u32
  #   r.text "user=admin method=password"
  #   r.return_success
  # end
  #
  # FreeBSD::Casper::AuditHelper::Event.write_activity(
  #   FreeBSD::Audit::Authentication::Activity::Logon
  # ) do |r|
  #   r.subject
  #   r.text "user=admin"
  #   r.address "203.0.113.42"
  #   r.return_success
  # end
  # ```
  module AuditHelper
    # -------------------------------------------------------------------------
    # Wire token — one per BSM record token type.
    #
    # `kind` is the type tag: "text" | "subject" | "address" | "return".
    # All optional numeric fields use `UInt64?` because `NVList::Serializable`'s
    # generated decoder only has a `read_number?` path for `UInt64?`; other
    # nilable integer types fall into the nested-nvlist branch which is wrong
    # for scalars. The server casts to `UInt32` / `Int32` / `UInt8` as needed.
    # -------------------------------------------------------------------------
    struct Token
      getter kind : String   # "text" | "subject" | "address" | "return"

      # "text" fields
      getter text : String?

      # "subject" fields — captured from the sandboxed caller so the helper
      # writes the caller's credentials, not its own.
      getter uid      : UInt64?
      getter egid     : UInt64?
      getter ruid     : UInt64?
      getter rgid     : UInt64?
      getter pid      : UInt64?
      getter session  : UInt64?
      getter terminal : String?   # dotted IPv4 or colon-sep IPv6; nil = no terminal

      # "address" fields
      getter addr : String?

      # "return" fields
      getter status : UInt64?   # 0 = success, 1 = failure
      getter retval : UInt64?

      def initialize(
        @kind : String,
        @text : String? = nil,
        @uid : UInt64? = nil,
        @egid : UInt64? = nil,
        @ruid : UInt64? = nil,
        @rgid : UInt64? = nil,
        @pid : UInt64? = nil,
        @session : UInt64? = nil,
        @terminal : String? = nil,
        @addr : String? = nil,
        @status : UInt64? = nil,
        @retval : UInt64? = nil,
      )
      end

      # Encode only the fields that are non-nil (plus the mandatory `kind`).
      # Skipping nil fields avoids null-typed nvlist entries that confuse
      # the string/number readers on decode.
      def to_nvlist_fields(b : FreeBSD::NVList::Builder) : Nil
        b.field("kind", @kind)
        b.field("text", @text) if @text
        b.field("uid", @uid) if @uid
        b.field("egid", @egid) if @egid
        b.field("ruid", @ruid) if @ruid
        b.field("rgid", @rgid) if @rgid
        b.field("pid", @pid) if @pid
        b.field("session", @session) if @session
        b.field("terminal", @terminal) if @terminal
        b.field("addr", @addr) if @addr
        b.field("status", @status) if @status
        b.field("retval", @retval) if @retval
      end

      def to_nvlist(b : FreeBSD::NVList::Builder, key : String) : Nil
        b.nvlist(key) { |child| to_nvlist_fields(child) }
      end

      def self.from_nvlist(pull : FreeBSD::NVList::PullParser) : self
        new(pull)
      end

      # Decode from a PullParser. Uses optional readers so absent fields yield nil.
      def initialize(pull : FreeBSD::NVList::PullParser)
        @kind     = pull.read_string("kind")
        @text     = pull.read_string?("text")
        @uid      = pull.read_number?("uid")
        @egid     = pull.read_number?("egid")
        @ruid     = pull.read_number?("ruid")
        @rgid     = pull.read_number?("rgid")
        @pid      = pull.read_number?("pid")
        @session  = pull.read_number?("session")
        @terminal = pull.read_string?("terminal")
        @addr     = pull.read_string?("addr")
        @status   = pull.read_number?("status")
        @retval   = pull.read_number?("retval")
      end

      # Named constructors -------------------------------------------------------

      def self.text(message : String) : self
        new(kind: "text", text: message)
      end

      def self.subject(uid : UInt64, egid : UInt64, ruid : UInt64, rgid : UInt64,
                       pid : UInt64, session : UInt64, terminal : String?) : self
        new(kind: "subject",
            uid: uid, egid: egid, ruid: ruid, rgid: rgid,
            pid: pid, session: session, terminal: terminal)
      end

      def self.address(addr : String) : self
        new(kind: "address", addr: addr)
      end

      def self.return_ok(ret : UInt32 = 0_u32) : self
        new(kind: "return", status: 0_u64, retval: ret.to_u64)
      end

      def self.return_fail(errno : UInt32 = 0_u32) : self
        new(kind: "return", status: 1_u64, retval: errno.to_u64)
      end
    end

    # -------------------------------------------------------------------------
    # Wire request — manual encode/decode because Array(Token) deserialization
    # is not handled by NVList::Serializable (no Array#initialize(pull)).
    #
    # Tokens are encoded as numbered binary blobs ("t0", "t1", ...) where each
    # blob is a packed Token nvlist produced by Codec::NVList.encode.
    # -------------------------------------------------------------------------
    struct Request
      getter event  : UInt16
      getter tokens : Array(Token)
      getter write  : Bool   # true = AU_TO_WRITE, false = AU_TO_NO_WRITE

      def initialize(@event : UInt16, @tokens : Array(Token), @write : Bool)
      end

      def to_nvlist_fields(b : FreeBSD::NVList::Builder) : Nil
        b.field("event", @event.to_u64)
        b.field("write", @write)
        b.field("count", @tokens.size.to_u64)
        @tokens.each_with_index do |tok, i|
          b.field("t#{i}", Casper::Codec::NVList.encode(tok))
        end
      end

      def self.from_nvlist(pull : FreeBSD::NVList::PullParser) : self
        new(pull)
      end

      def initialize(pull : FreeBSD::NVList::PullParser)
        @event = pull.read_number("event").to_u16
        @write = pull.read_bool("write")
        count  = pull.read_number("count").to_i
        @tokens = Array(Token).new(count) do |i|
          Casper::Codec::NVList.decode(pull.read_binary("t#{i}"), Token)
        end
      end
    end

    # -------------------------------------------------------------------------
    # Wire response
    # -------------------------------------------------------------------------
    struct Response
      getter ok      : Bool
      getter message : String?

      def initialize(@ok : Bool, @message : String? = nil)
      end

      def to_nvlist_fields(b : FreeBSD::NVList::Builder) : Nil
        b.field("ok", @ok)
        b.field("message", @message) if @message
      end

      def to_nvlist(b : FreeBSD::NVList::Builder, key : String) : Nil
        b.nvlist(key) { |child| to_nvlist_fields(child) }
      end

      def self.from_nvlist(pull : FreeBSD::NVList::PullParser) : self
        new(pull)
      end

      def initialize(pull : FreeBSD::NVList::PullParser)
        @ok      = pull.read_bool("ok")
        @message = pull.read_string?("message")
      end
    end

    # -------------------------------------------------------------------------
    # TokenBuffer — client-side record builder.
    #
    # Mirrors the public API of `FreeBSD::Audit::Record` so callers can swap
    # `Event.write` ↔ `AuditHelper::Event.write` with minimal changes.
    # Credentials (uid, egid, ruid, rgid, pid) are captured at call time in the
    # sandboxed process and passed over the wire, so the privileged helper writes
    # the caller's credentials.
    # -------------------------------------------------------------------------
    class TokenBuffer
      include FreeBSD::Audit::AuditRecordBuilder

      getter tokens : Array(Token) = Array(Token).new

      # Append a text token.
      def text(message : String) : Nil
        @tokens << Token.text(message)
      end

      # Append a subject token. Defaults mirror `FreeBSD::Audit::Record#subject`.
      def subject(
        uid : UInt32 = {% if flag?(:freebsd) || flag?(:dragonfly) %}
                         LibBsm.geteuid.to_u32
                       {% else %}
                         LibC.getuid.to_u32
                       {% end %},
        pid : Int32 = Process.pid.to_i32,
        session : UInt32 = 0_u32,
        terminal : String? = nil,
      ) : Nil
        egid = {% if flag?(:freebsd) || flag?(:dragonfly) %}
                 LibBsm.getegid.to_u64
               {% else %}
                 0_u64
               {% end %}
        ruid = LibC.getuid.to_u64
        rgid = {% if flag?(:freebsd) || flag?(:dragonfly) %}
                 LibBsm.getgid.to_u64
               {% else %}
                 0_u64
               {% end %}
        @tokens << Token.subject(uid.to_u64, egid, ruid, rgid, pid.to_u64, session.to_u64, terminal)
      end

      # Append an address token. Accepts dotted IPv4 or colon-sep IPv6.
      def address(addr : String) : Nil
        @tokens << Token.address(addr)
      end

      # Append a successful return token.
      def return_success(ret : UInt32 = 0_u32) : Nil
        @tokens << Token.return_ok(ret)
      end

      # Append a failure return token. For a well-typed constant use the
      # `return_failure(Errno)` overload provided by `AuditRecordBuilder`.
      def return_failure(errno : UInt32 = 0_u32) : Nil
        @tokens << Token.return_fail(errno)
      end
    end

    # -------------------------------------------------------------------------
    # Event — drop-in for FreeBSD::Audit::Event when inside a Capsicum sandbox.
    #
    # Requires `FreeBSD::Casper.audit_helper!` to be installed (either via
    # `register_audit_helper` or `install_audit_helper`).
    # -------------------------------------------------------------------------
    module Event
      # Open an audit record for *event*, yield a `TokenBuffer` to build tokens,
      # then commit the record via the privileged helper.
      def self.write(event : FreeBSD::Audit::AUE, & : TokenBuffer ->) : Nil
        send_request(event, write: true) { |buf| yield buf }
      end

      # Same as `#write` but discards the record without writing to the audit
      # trail. Useful for testing token construction without a live auditd.
      def self.discard(event : FreeBSD::Audit::AUE, & : TokenBuffer ->) : Nil
        send_request(event, write: false) { |buf| yield buf }
      end

      # Open an audit record for an OCSF activity, write the `activity_id`
      # token automatically, then commit via the helper.
      def self.write_activity(activity : T, & : TokenBuffer ->) : Nil forall T
        write(activity.aue) do |buf|
          buf.activity_id(activity.value, activity.to_s)
          yield buf
        end
      end

      # Same as `#write_activity` but discards the record.
      def self.discard_activity(activity : T, & : TokenBuffer ->) : Nil forall T
        discard(activity.aue) do |buf|
          buf.activity_id(activity.value, activity.to_s)
          yield buf
        end
      end

      private def self.send_request(event : FreeBSD::Audit::AUE, write : Bool, & : TokenBuffer ->) : Nil
        client = FreeBSD::Casper.audit_helper!
        buf = TokenBuffer.new
        yield buf
        req  = Request.new(event: event.value, tokens: buf.tokens, write: write)
        resp = client.request(req, Response)
        raise FreeBSD::Audit::SystemError.new(resp.message || "audit helper error") unless resp.ok
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Global state — mirrors syslog.cr
  # ---------------------------------------------------------------------------

  @@audit_helper : Helper::Client(Codec::NVList)? = nil

  # The globally-installed audit helper client, if any.
  def self.audit_helper? : Helper::Client(Codec::NVList)?
    @@audit_helper
  end

  # Like `#audit_helper?` but raises if no helper is installed.
  def self.audit_helper! : Helper::Client(Codec::NVList)
    @@audit_helper || raise "FreeBSD::Casper audit helper not installed — call register_audit_helper"
  end

  # Register *client* as the process-wide audit helper.
  def self.install_audit_helper(client : Helper::Client(Codec::NVList)) : Nil
    @@audit_helper = client
  end

  # Remove the installed audit helper.
  def self.uninstall_audit_helper : Nil
    @@audit_helper = nil
  end

  # ---------------------------------------------------------------------------
  # register_audit_helper macro
  #
  # Inject a Crystal.main_user_code override that forks a privileged helper via
  # pdfork before the Crystal runtime starts. The helper handles
  # AuditHelper::Request messages by replaying the token list through libbsm.
  #
  # ```crystal
  # require "freebsd/casper/audit_helper"
  #
  # FreeBSD::Casper.register_audit_helper
  #
  # FreeBSD::Capsicum.sandbox!
  #
  # FreeBSD::Casper::AuditHelper::Event.write(FreeBSD::Audit::AUE::Authentication) do |r|
  #   r.subject
  #   r.text "user=admin"
  #   r.return_success
  # end
  # ```
  # ---------------------------------------------------------------------------
  macro register_audit_helper(name = "audit")
    # 1. Fork the helper. Helper.register injects its own Crystal.main_user_code
    #    override that pdforks before the runtime. In the helper child the block
    #    runs (register handler + serve_typed). In the parent the client socket
    #    is stored in Helper._clients[name].
    FreeBSD::Casper::Helper.register(name: {{name}}) do |_audit_server|
      _audit_server.on(FreeBSD::Casper::AuditHelper::Request) do |req|
        \{% if flag?(:freebsd) || flag?(:dragonfly) %}
          begin
            d = LibBsm.au_open
            if d == -1
              FreeBSD::Casper::AuditHelper::Response.new(ok: false, message: "au_open failed (errno #{Errno.value})")
            else
              req.tokens.each do |tok|
                # Construct the BSM token and write it. Mirror Record#write_token:
                # au_write takes ownership on success (return 0); on failure (-1)
                # the token is untouched and must be freed by the caller.
                # Unknown kind values are skipped without producing a token.
                next unless tok.kind == "text" || tok.kind == "subject" ||
                            tok.kind == "address" || tok.kind == "return"
                t : LibBsm::AuToken = case tok.kind
                                      when "text"
                                        LibBsm.au_to_text(tok.text.not_nil!)
                                      when "subject"
                                        auid = LibBsm::AU_NOAUDITID
                                        uid  = tok.uid.not_nil!.to_u32
                                        egid = tok.egid.not_nil!.to_u32
                                        ruid = tok.ruid.not_nil!.to_u32
                                        rgid = tok.rgid.not_nil!.to_u32
                                        pid  = tok.pid.not_nil!.to_i32
                                        sid  = tok.session.not_nil!.to_u32
                                        if term = tok.terminal
                                          if term.includes?(':')
                                            tid6 = LibBsm::AuTidAddr.new(at_port: 0_u32, at_type: 16_u32)
                                            LibBsm.inet_pton(Socket::Family::INET6.value, term,
                                                             tid6.at_addr.to_unsafe.as(Void*))
                                            LibBsm.au_to_subject32_ex(auid, uid, egid, ruid, rgid,
                                                                        pid, sid, pointerof(tid6))
                                          else
                                            in4 = LibC::InAddr.new
                                            LibBsm.inet_pton(Socket::Family::INET.value, term,
                                                             pointerof(in4).as(Void*))
                                            tid4 = LibBsm::AuTid.new(port: 0_u32, machine: in4.s_addr)
                                            LibBsm.au_to_subject32(auid, uid, egid, ruid, rgid,
                                                                     pid, sid, pointerof(tid4))
                                          end
                                        else
                                          tid4 = LibBsm::AuTid.new(port: 0_u32, machine: 0_u32)
                                          LibBsm.au_to_subject32(auid, uid, egid, ruid, rgid,
                                                                   pid, sid, pointerof(tid4))
                                        end
                                      when "address"
                                        addr_str = tok.addr.not_nil!
                                        if addr_str.includes?(':')
                                          in6 = LibC::In6Addr.new
                                          LibBsm.inet_pton(Socket::Family::INET6.value, addr_str,
                                                           pointerof(in6).as(Void*))
                                          LibBsm.au_to_in_addr_ex(pointerof(in6))
                                        else
                                          in4 = LibC::InAddr.new
                                          LibBsm.inet_pton(Socket::Family::INET.value, addr_str,
                                                           pointerof(in4).as(Void*))
                                          LibBsm.au_to_in_addr(pointerof(in4))
                                        end
                                      else # "return"
                                        LibBsm.au_to_return32(tok.status.not_nil!.to_u8,
                                                              tok.retval.not_nil!.to_u32)
                                      end
                if LibBsm.au_write(d, t) == -1
                  LibBsm.au_free_token(t)
                end
              end
              keep = req.write ? LibBsm::AU_TO_WRITE : LibBsm::AU_TO_NO_WRITE
              LibBsm.au_close(d, keep, req.event)
              FreeBSD::Casper::AuditHelper::Response.new(ok: true)
            end
          rescue ex
            FreeBSD::Casper::AuditHelper::Response.new(ok: false, message: ex.message)
          end
        \{% else %}
          FreeBSD::Casper::AuditHelper::Response.new(ok: false, message: "unsupported platform")
        \{% end %}
      end
      _audit_server.serve_typed
    end

    # Install the client in the parent at top-level init time, right after
    # Helper.register's top-level else-branch has registered it in _clients.
    # This must happen here (not in a Crystal.main_user_code override) because
    # Helper.register's main_user_code closes _clients after previous_def returns.
    \{% if flag?(:freebsd) || flag?(:dragonfly) %}
      unless FreeBSD::Casper::Helper.is_helper
        FreeBSD::Casper.install_audit_helper(
          FreeBSD::Casper::Helper.client({{name}})
        )
      end
    \{% end %}
  end
end
