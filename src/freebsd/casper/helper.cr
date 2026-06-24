require "socket"
require "./codec/nvlist"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  lib LibC
    fun setproctitle(fmt : LibC::Char*, ...) : Void
    fun getprogname : LibC::Char*
  end
{% end %}

module FreeBSD::Casper
  # Custom FreeBSD::Casper-style privsep helpers, written in Crystal.
  #
  # `FreeBSD::Casper::Helper.spawn { |server| ... }` forks a trusted helper process
  # that runs the block (serving requests). The calling process receives a
  # `Client` and continues — typically sandboxing itself and issuing requests
  # to the helper. The two halves communicate over a `UNIXSocket` pair using
  # a small length-prefixed wire protocol — the same architecture `casperd`
  # and its services use, just written in pure Crystal so you don't have to
  # ship a `.so` plugin to `casperd`.
  #
  # On FreeBSD/DragonFly the helper's process title is set to
  # `progname.name` (e.g. `myapp.calc`), matching the `system.net` convention
  # used by `casperd` service workers. Unnamed helpers use `progname.helper`.
  #
  # **Raw API** — full control, no serialization:
  # ```
  # client = FreeBSD::Casper::Helper.spawn(name: "files") do |server|
  #   server.serve do |op, payload|
  #     case op
  #     when "ping" then "pong".to_slice
  #     else             raise "unknown op: #{op}"
  #     end
  #   end
  # end
  # String.new(client.request("ping")) # => "pong"
  # # ps shows: myapp.files
  # ```
  #
  # **Typed API** — structs + `FreeBSD::NVList::Serializable` (default codec):
  # ```
  # record Req, path : String do
  #   include FreeBSD::NVList::Serializable
  # end
  # record Resp, data : String do
  #   include FreeBSD::NVList::Serializable
  # end
  #
  # client = FreeBSD::Casper::Helper.spawn(name: "files") do |server|
  #   server.on(Req) { |r| Resp.new(data: File.read(r.path)) }
  #   server.serve_typed
  # end
  # client.request(Req.new(path: "/etc/hosts"), Resp).data # => String
  # ```
  #
  # **Custom codec** — pass `codec: FreeBSD::Casper::Codec::JSON` (or YAML, or any
  # module with `encode`/`decode` class methods) to use a different serializer:
  # ```
  # require "freebsd/casper/codec/json"
  # client = FreeBSD::Casper::Helper.spawn(codec: FreeBSD::Casper::Codec::JSON) do |server|
  #   ...
  # end
  # ```
  #
  # Errors raised inside the helper's serve block are caught and sent back
  # to the client as `Helper::RemoteError`.
  module Helper
    # Raised when the helper's handler raised — message carries the error text.
    class RemoteError < ::FreeBSD::Capsicum::Error
    end

    # Wire format (both halves run on the same machine; host byte order is fine):
    #
    #   op_len      : UInt32   # byte length of op string
    #   op          : UTF-8 bytes
    #   payload_len : UInt32
    #   payload     : bytes
    #
    # Response:
    #   status      : UInt8    # 0 = ok, 1 = error
    #   payload_len : UInt32
    #   payload     : bytes
    private FORMAT = IO::ByteFormat::BigEndian

    # Internal state threaded through the pdfork boundary.
    # These are set in main_user_code (before runtime) and read in __crystal_main.
    #
    # Multiple helpers compose: each `register` chains a `Crystal.main_user_code`
    # override that pdforks a child. A child boots the runtime via `previous_def`,
    # so it cannot serve from inside the fork closure (no event loop yet) — it must
    # defer serving to a top-level block that runs once the runtime is up. To keep
    # the *N* helpers' children apart, state is keyed per-registration:
    #
    #   * `@@active_helper` — set in the pdfork closure to the registration's name,
    #     so each child knows *which* registration it is the helper for. The parent
    #     leaves it `nil`. A top-level `register` block serves only when it matches.
    #   * `@@helper_fds` / `@@client_fds` — the child/parent ends of each
    #     registration's socketpair, keyed by name, so a later `register` cannot
    #     clobber an earlier one's fd.
    #   * `@@pds` — the parent's process descriptors, one per registration, all
    #     waited/closed at exit.
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      # NOTE: the collection-valued state below is touched from `main_user_code`,
      # which the runtime calls *before* `__crystal_main` — and class-var
      # initializer expressions (`Hash.new`, `[] of …`) only run inside
      # `__crystal_main`. Eagerly-initialized class vars would therefore be
      # accessed before their initializer ran (a segfault on first write). So
      # each is declared `nil` and lazily allocated through its accessor, which
      # is safe whenever first touched — pre- or post-runtime. `active_helper`
      # is a plain `String?` (compile-time nil) and needs no laziness.
      @@active_helper : String? = nil
      @@helper_fds : Hash(String, Int32)? = nil
      @@client_fds : Hash(String, Int32)? = nil
      @@pds : Array(FreeBSD::Capsicum::ProcessDescriptor)? = nil
      @@_clients : Hash(String, Client(Codec::NVList))? = nil

      # :nodoc:
      # The name of the registration this process is the helper child for, or
      # `nil` in the parent (client) process.
      def self.active_helper=(v : String?)
        @@active_helper = v
      end

      # :nodoc:
      def self.active_helper : String?
        @@active_helper
      end

      # :nodoc:
      # True in any pdfork'd helper child (i.e. once `active_helper` is set).
      # Casper service macros (`register_net`, …) guard on this to avoid running
      # cap_init in a child that owns no Casper channel.
      def self.is_helper : Bool
        !@@active_helper.nil?
      end

      # :nodoc:
      def self.helper_fds : Hash(String, Int32)
        @@helper_fds ||= Hash(String, Int32).new
      end

      # :nodoc:
      def self.client_fds : Hash(String, Int32)
        @@client_fds ||= Hash(String, Int32).new
      end

      # :nodoc:
      def self.pds : Array(FreeBSD::Capsicum::ProcessDescriptor)
        @@pds ||= [] of FreeBSD::Capsicum::ProcessDescriptor
      end

      # :nodoc:
      def self._register_client(name : String, c : Client(Codec::NVList)) : Nil
        _clients[name] = c
      end

      # :nodoc:
      def self._clients : Hash(String, Client(Codec::NVList))
        @@_clients ||= Hash(String, Client(Codec::NVList)).new
      end
    {% end %}

    # Install a privileged helper process using `pdfork(2)`.
    #
    # Call at the **top level** of your program (outside any method). The macro
    # injects a `Crystal.main_user_code` override that forks the helper before
    # the Crystal runtime starts, then initialises the runtime independently in
    # both the helper child and the client parent.
    #
    # The block receives a `Server` and should call `server.serve { }` or
    # `server.serve_typed` to handle requests. Full Crystal IO is available
    # inside the block (unlike `spawn_early`).
    #
    # Install a privileged helper process using `pdfork(2)`.
    #
    # Call at the **top level** of your program (outside any method). The macro
    # injects a `Crystal.main_user_code` override that forks the helper before
    # the Crystal runtime starts, then initialises the runtime independently in
    # both the helper child and the client parent.
    #
    # The block receives a `Server` and should call `server.serve { }` or
    # `server.serve_typed` to handle requests. Full Crystal IO is available
    # inside the block (unlike `spawn_early`). The child exits when serving ends.
    #
    # After `register`, retrieve the connected `Client` in the parent process
    # via `FreeBSD::Casper::Helper.client`.
    #
    # ```
    # FreeBSD::Casper::Helper.register(name: "files") do |server|
    #   server.serve do |op, payload|
    #     case op
    #     when "read" then File.read(String.new(payload)).to_slice
    #     when "ping" then "pong".to_slice
    #     else             raise "unknown op: #{op}"
    #     end
    #   end
    # end
    #
    # client = FreeBSD::Casper::Helper.client(name: "files")
    # FreeBSD::Capsicum.sandbox!
    # String.new(client.request("ping")) # => "pong"
    # ```
    macro register(name = "", &block)
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        def Crystal.main_user_code(argc : Int32, argv : UInt8**)
          # Only the parent forks. A pdfork'd child (active_helper already set by
          # an outer override) must NOT fork again — it just boots the runtime via
          # previous_def and lets the chain unwind, so each registration produces
          # exactly one child. Without this guard the first child would re-run the
          # whole chain and fork a child per remaining registration.
          if FreeBSD::Casper::Helper.active_helper
            previous_def
            return
          end

          fds = uninitialized LibC::Int[2]
          if LibC.socketpair(LibC::AF_UNIX, LibC::SOCK_STREAM, 0, fds) != 0
            raise FreeBSD::Capsicum::Error.from_errno("socketpair")
          end

          pd = FreeBSD::Capsicum.pdfork do
            LibC.close(fds[0])
            FreeBSD::Casper::Helper.helper_fds[{{ name }}] = fds[1]
            # Mark this process as *this* registration's helper child, then boot
            # the runtime. The matching top-level block below serves the loop.
            FreeBSD::Casper::Helper.active_helper = {{ name }}
            previous_def
            0
          end

          LibC.close(fds[1])
          FreeBSD::Casper::Helper.client_fds[{{ name }}] = fds[0]
          FreeBSD::Casper::Helper.pds << pd
          previous_def
          # Parent cleanup, after the body returns. With N registrations this
          # block is emitted once per frame and they share `_clients`/`pds`, so
          # it must be idempotent: drain `pds` (each child waited/closed exactly
          # once) and close each client only once. The outer frames then find
          # both already empty/closed.
          FreeBSD::Casper::Helper._clients.each_value { |c| c.close unless c.closed? }
          while _pd = FreeBSD::Casper::Helper.pds.shift?
            _pd.wait
            _pd.close
          end
        end

        if FreeBSD::Casper::Helper.active_helper == {{ name }}
          # We are the child forked for this registration: serve its block.
          _helper_sock = UNIXSocket.new(fd: FreeBSD::Casper::Helper.helper_fds[{{ name }}],
                                        type: Socket::Type::STREAM)
          {% unless name.empty? %}
            LibC.setproctitle("- %s", (String.new(LibC.getprogname) + ".{{name.id}}").to_unsafe)
          {% end %}
          _server = FreeBSD::Casper::Helper::Server(FreeBSD::Casper::Codec::NVList).new(_helper_sock)
          {{ block.args[0].id }} = _server
          {{ block.body }}
          _helper_sock.close
          exit(0)
        elsif FreeBSD::Casper::Helper.active_helper.nil?
          # Parent process: connect a client to this registration's helper.
          FreeBSD::Casper::Helper._register_client(
            {{name}},
            FreeBSD::Casper::Helper::Client(FreeBSD::Casper::Codec::NVList).new(
              UNIXSocket.new(fd: FreeBSD::Casper::Helper.client_fds[{{ name }}],
                             type: Socket::Type::STREAM),
              {{name}}))
        end
        # A child whose active_helper != this name falls through: it is some other
        # registration's helper and must not touch this one's socket.
      {% end %}
    end

    # Returns the `Client` connected to the named registered helper.
    # Only valid in the client (parent) process after `register(name:)` has run.
    # Raises if no helper with the given name was registered.
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      def self.client(name : String) : Client(Codec::NVList)
        _clients[name]? || raise "Helper.client: no helper registered as #{name.inspect}"
      end
    {% end %}

    # Fork a helper process that runs the block (server side). Returns a
    # `Client(Casper::Codec::NVList)` in the calling process. The forked
    # helper exits when the block returns.
    #
    # `name:` is an optional service label. On FreeBSD/DragonFly it sets the
    # helper's process title to `progname.name` (e.g. `myapp.calc`), mirroring
    # the `system.dns` naming used by `casperd` workers. The name is also
    # available on the returned `Client#name` and appears in STDERR error output.
    def self.spawn(name : String = "", & : Server(Codec::NVList) ->) : Client(Codec::NVList)
      do_spawn(Codec::NVList, name) { |s| yield s } # ameba:disable Naming/BlockParameterName
    end

    # Fork a helper process using an explicit codec. Pass `codec: Casper::Codec::JSON`
    # (require `"freebsd/casper/codec/json"` first) or any module implementing
    # `encode(value) : Bytes` and `decode(bytes, T.class) : T` class methods.
    # The raw `serve`/`request(String, Bytes)` API is unaffected by the codec.
    # See `#spawn(name:)` for `name:` semantics.
    def self.spawn(codec : C.class, name : String = "", & : Server(C) ->) : Client(C) forall C
      do_spawn(codec, name) { |s| yield s } # ameba:disable Naming/BlockParameterName
    end

    # Fork a helper via `pdfork(2)` before the Crystal runtime starts.
    #
    # Call this from a `Crystal.main_user_code` override **before** `previous_def`
    # — i.e. before `__crystal_main` runs, while the event loop and fiber scheduler
    # do not exist yet. Uses raw `LibC.socketpair` so no event-loop interaction
    # happens before the fork, and `LibC._exit` in the child so GC finalizers
    # don't run and corrupt the parent's state.
    #
    # **I/O in the helper block** must use blocking syscalls (`LibC.open` /
    # `LibC.read` / `LibC.close`) rather than Crystal's IO abstractions.
    # Crystal IO (`File.read`, `IO::FileDescriptor`, etc.) routes through the
    # event loop, which doesn't exist in the child.
    #
    # Returns `{client, pd}` — a `Client` to make requests with and a
    # `ProcessDescriptor` to wait on. Call `pd.wait; pd.close` after `previous_def`
    # (once the runtime is up) to reap the helper.
    #
    # On FreeBSD/DragonFly the helper's process title is set to `progname.name`.
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
    def self.spawn_early(name : String = "",
                         & : Server(Codec::NVList) ->) : {Client(Codec::NVList), FreeBSD::Capsicum::ProcessDescriptor}
      do_spawn_early(Codec::NVList, name) { |s| yield s }
    end

    # Fork a helper early with an explicit codec. See `#spawn_early` for details.
    def self.spawn_early(codec : C.class, name : String = "",
                         & : Server(C) ->) : {Client(C), FreeBSD::Capsicum::ProcessDescriptor} forall C
      do_spawn_early(codec, name) { |s| yield s }
    end

    private def self.do_spawn_early(codec : C.class, name : String,
                                    & : Server(C) ->) : {Client(C), FreeBSD::Capsicum::ProcessDescriptor} forall C
      # Use raw socketpair(2) — UNIXSocket.pair touches the event loop which
      # doesn't exist yet at this call site.
      fds = uninitialized LibC::Int[2]
      if LibC.socketpair(LibC::AF_UNIX, LibC::SOCK_STREAM, 0, fds) != 0
        raise ::FreeBSD::Capsicum::Error.from_errno("socketpair")
      end
      client_fd = fds[0]
      helper_fd = fds[1]

      pd = FreeBSD::Capsicum.pdfork do
        LibC.close(client_fd)
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          progname = String.new(LibC.getprogname)
          title = name.empty? ? "#{progname}.helper" : "#{progname}.#{name}"
          LibC.setproctitle("- %s", title.to_unsafe)
        {% end %}
        helper_sock = UNIXSocket.new(fd: helper_fd, type: Socket::Type::STREAM)
        # Force blocking: the child has no event loop, so reads must block in-kernel.
        Crystal::System::Socket.set_blocking(helper_fd, true)
        server = Server(C).new(helper_sock)
        begin
          yield server
        rescue ex
          label = name.empty? ? "helper" : "helper[#{name}]"
          STDERR.puts "#{label}:"
          ex.inspect_with_backtrace(STDERR)
          STDERR.flush
        ensure
          helper_sock.close
        end
        0
      end

      LibC.close(helper_fd)
      client_sock = UNIXSocket.new(fd: client_fd, type: Socket::Type::STREAM)
      {Client(C).new(client_sock, name), pd}
    end
    {% end %}

    private def self.do_spawn(codec : C.class, name : String, & : Server(C) ->) : Client(C) forall C
      # UNIXSocket.pair — both ends are registered in the event loop so the
      # serve loop can use non-blocking IO normally after Process.fork.
      client_sock, helper_sock = UNIXSocket.pair

      _child_proc = Process.fork do
        client_sock.close
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          progname = String.new(LibC.getprogname)
          title = name.empty? ? "#{progname}.helper" : "#{progname}.#{name}"
          LibC.setproctitle("- %s", title.to_unsafe)
        {% end %}
        server = Server(C).new(helper_sock)
        begin
          yield server
        rescue ex
          label = name.empty? ? "helper" : "helper[#{name}]"
          STDERR.puts "#{label}:"
          ex.inspect_with_backtrace(STDERR)
          STDERR.flush
        ensure
          helper_sock.close
        end
      end

      helper_sock.close
      Client(C).new(client_sock, name)
    end

    # Caller-side handle to the forked helper. Issue `request`s; receive
    # `Bytes` replies. Thread-safety: a single `Client` does not multiplex
    # requests; if you need concurrency, build a queue around it.
    class Client(C)
      # Optional name given at spawn time. Empty string if none was provided.
      getter name : String

      def initialize(@io : UNIXSocket, @name : String = "")
      end

      # Send `op` + `payload`, block until the helper replies. Raises
      # `RemoteError` if the helper's handler raised.
      def request(op : String, payload : Bytes = Bytes.empty) : Bytes
        op_bytes = op.to_slice
        @io.write_bytes(op_bytes.size.to_u32, FORMAT)
        @io.write(op_bytes)
        @io.write_bytes(payload.size.to_u32, FORMAT)
        @io.write(payload)
        @io.flush

        status = @io.read_byte || raise IO::EOFError.new("helper closed")
        size = @io.read_bytes(UInt32, FORMAT)
        buf = Bytes.new(size)
        @io.read_fully(buf)
        if status == 0_u8
          buf
        else
          raise RemoteError.new(String.new(buf))
        end
      end

      # Typed request. Encodes `payload` with codec `C` using `T.name` as the
      # op key, and decodes the reply as `R`. Both `T` and `R` must be
      # serializable by `C`. Raises `RemoteError` if the helper raised.
      def request(payload : T, response_type : R.class) : R forall T, R
        raw_reply = request(T.name, C.encode(payload))
        C.decode(raw_reply, R)
      end

      # Close the socket to the helper. The helper's `#serve` loop will see EOF
      # and return; the helper process exits cleanly.
      def close : Nil
        @io.close
      end

      # True if the socket to the helper has been closed.
      def closed? : Bool
        @io.closed?
      end

      # Underlying socket fd. Safe to pass to `cap_rights_limit`.
      def to_unsafe : Int32
        @io.fd
      end
    end

    # Helper-side handle. The block passed to `#serve` runs once per request
    # and must return the reply payload as `Bytes`. Exceptions are caught
    # and sent back to the client as a `RemoteError`.
    class Server(C)
      @handlers = Hash(String, Proc(Bytes, Bytes)).new

      def initialize(@io : UNIXSocket)
      end

      # Register a typed handler for request type `T`. The op key on the wire
      # is `T.name` (fully-qualified, e.g. `"MyApp::ReadReq"`). `T` must be
      # decodable by codec `C`; the handler's return type `R` must be encodable.
      # Registering the same `T` twice replaces the earlier handler.
      def on(request_type : T.class, &handler : T -> R) : Nil forall T, R
        @handlers[T.name] = Proc(Bytes, Bytes).new do |raw|
          C.encode(handler.call(C.decode(raw, T)))
        end
      end

      # Dispatch loop using registered handlers. Routes each request by
      # `T.name` to the handler registered with `#on`. Unknown ops raise
      # `ArgumentError` (propagated to the caller as `RemoteError`). Returns
      # when the client closes its socket.
      def serve_typed : Nil
        serve do |op, payload|
          handler = @handlers[op]? || raise ArgumentError.new("unknown op: #{op}")
          handler.call(payload)
        end
      end

      # Read-dispatch loop. Reads one request at a time, yields `(op, payload)`,
      # and writes the returned `Bytes` as the reply. Returns when the client
      # closes its socket (clean EOF). Exceptions from the block are caught and
      # sent back as error responses.
      def serve(& : (String, Bytes) -> Bytes) : Nil
        size_buf = Bytes.new(4)
        loop do
          n = @io.read(size_buf)
          break if n == 0 # clean EOF — client disconnected
          raise IO::EOFError.new("partial header (#{n} of 4 bytes)") if n != 4
          op_size = FORMAT.decode(UInt32, size_buf)
          op_buf = Bytes.new(op_size)
          @io.read_fully(op_buf)
          op = String.new(op_buf)
          payload_size = @io.read_bytes(UInt32, FORMAT)
          payload = Bytes.new(payload_size)
          @io.read_fully(payload)

          begin
            reply = yield op, payload
            write_response(0_u8, reply)
          rescue ex
            msg = (ex.message || ex.class.name).to_slice
            write_response(1_u8, msg)
          end
        end
      end

      def close : Nil
        @io.close
      end

      private def write_response(status : UInt8, payload : Bytes) : Nil
        @io.write_byte(status)
        @io.write_bytes(payload.size.to_u32, FORMAT)
        @io.write(payload)
        @io.flush
      end
    end
  end
end
