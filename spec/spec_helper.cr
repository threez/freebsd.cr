require "spec"
require "../src/freebsd/casper"

# Skip examples that need a working Capsicum/libcasper when running on a
# non-supporting platform. Use `it_on_capsicum "does X" do ... end` instead of
# the bare `it`.
macro it_on_capsicum(description, &block)
  {% if flag?(:freebsd) || flag?(:dragonfly) %}
    it {{ description }} do
      {{ block.body }}
    end
  {% else %}
    pending {{ description }} + " (requires FreeBSD)"
  {% end %}
end

# True iff the running OS supports Capsicum at all. Specs branch on this
# directly when they want to vary expectations rather than skip.
CAPSICUM_OS = {{ flag?(:freebsd) || flag?(:dragonfly) }}

# Run `block` in a forked child suitable for `FreeBSD::Capsicum.sandbox!` testing.
#
# Because `cap_enter(2)` is one-way per process, anything that calls
# `FreeBSD::Capsicum.sandbox!` must run in a forked child or it would render the test
# runner unusable. Uses `FreeBSD::Capsicum.pdfork` so the child is controlled via a
# process descriptor rather than a PID. This helper handles three things
# the bare fork pattern gets wrong:
#
# 1. The block runs inside `begin/rescue`. Any uncaught exception in the
#    child (including `Spec::AssertionFailed` from `should` matchers and
#    `expect_raises`) is serialized through a pipe and re-raised in the parent
#    — so you see *why* the child failed, not just "exit code 1".
# 2. The pipe uses a length-prefixed protocol (4-byte message length followed
#    by the error string) so the parent reads exactly what the child wrote,
#    regardless of any grandchildren (e.g. libcasper service workers, Helper
#    server processes) that inherited the write end.
# 3. Optionally, `before_wait` runs in the parent concurrently with the
#    child (useful when the parent owns a peer the child needs to talk to,
#    e.g. a `TCPServer.accept` for a Net spec).
#
# ```
# it_on_capsicum "blocks global namespace access after sandboxing" do
#   in_sandbox_child do
#     FreeBSD::Capsicum.sandbox!
#     expect_raises(File::Error) { File.open("/etc/hosts", "r") { } }
#   end
# end
# ```
def in_sandbox_child(*, before_wait : (-> Nil)? = nil, &block : -> _) : Nil
  reader, writer = IO.pipe
  child_block = block
  pd_fd = 0
  raw_pid = LibC::PidT.new(0)

  {% if flag?(:freebsd) || flag?(:dragonfly) %}
    raw_pid = LibPdfork.pdfork(pointerof(pd_fd), 0)
    raise RuntimeError.new("pdfork failed: #{Errno.value}") if raw_pid < 0

    if raw_pid == 0
      # Child: reinitialize the event loop and signal handlers, then restore
      # SIGPIPE to SIG_IGN so that writes to sockets whose peer has exited
      # (e.g. a Helper grandchild that finished serving) raise IO::Error
      # instead of killing the child.
      Process.after_fork_child_callbacks.each(&.call)
      LibC.signal(Signal::PIPE.value, LibC::SIG_IGN)
      reader.close
      begin
        child_block.call
        # success: zero-length message
        writer.write_bytes(0_u32, IO::ByteFormat::BigEndian)
      rescue ex
        msg = ex.inspect_with_backtrace
        bytes = msg.to_slice
        writer.write_bytes(bytes.size.to_u32, IO::ByteFormat::BigEndian)
        writer.write(bytes)
      end
      writer.flush
      writer.close
      LibC._exit(0)
    end

    writer.close
  {% else %}
    raise FreeBSD::Capsicum::UnsupportedPlatformError.new
  {% end %}

  pd = FreeBSD::Capsicum::ProcessDescriptor.new(pd_fd, raw_pid.to_i64)

  parent_err : Exception? = nil
  begin
    before_wait.try(&.call)
  rescue ex
    parent_err = ex
  end

  # Read exactly what the child wrote — not gets_to_end, so grandchildren
  # (libcasper service workers, Helper server) holding the write end
  # do not cause the parent to block indefinitely.
  len = reader.read_bytes(UInt32, IO::ByteFormat::BigEndian)
  error_msg = if len > 0
                buf = Bytes.new(len)
                reader.read_fully(buf)
                String.new(buf)
              end
  reader.close
  pd.wait
  pd.close

  raise parent_err if parent_err
  if msg = error_msg
    raise "sandbox child failed:\n#{msg}"
  end
end
