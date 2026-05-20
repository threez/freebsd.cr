module FreeBSD::Capsicum
  # A handle to a child process created by `pdfork(2)`. The process is
  # identified by a file descriptor rather than by its PID, which means it
  # can be controlled from inside capability mode (where the global PID
  # namespace is no longer available).
  #
  # The canonical privsep pattern using `ProcessDescriptor`:
  #
  # ```
  # require "freebsd/capsicum"
  #
  # pd = FreeBSD::Capsicum.pdfork do
  #   # Inside the child. Drop privileges, then sandbox.
  #   FreeBSD::Capsicum.sandbox!
  #   run_untrusted_work
  #   0
  # end
  #
  # # Inside the (unsandboxed) parent. `pd` is usable as a control handle
  # # even after the parent later sandboxes itself.
  # FreeBSD::Capsicum.sandbox!
  # pd.kill(Signal::TERM) if shutting_down?
  # pd.close # sends SIGKILL (if still running) and reaps
  # ```
  class ProcessDescriptor
    # File descriptor identifying the child process.
    getter fd : Int32

    # PID the child has in the global namespace. Useful for logging or for
    # `Process.wait` from an unsandboxed parent; not usable from inside
    # capability mode where the PID namespace is gone.
    getter pid : Int64

    @closed = false

    def initialize(@fd : Int32, @pid : Int64)
    end

    # Send `signal` to the child. Equivalent to `pdkill(2)`.
    def kill(signal : Signal = Signal::TERM) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        if LibPdfork.pdkill(@fd, signal.value) != 0
          raise Error.from_errno("pdkill")
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Refresh `pid` from the kernel via `pdgetpid(2)`. Returns `nil` if the
    # child has already exited and been reaped.
    def current_pid : Int64?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        pidp = LibC::PidT.new(0)
        if LibPdfork.pdgetpid(@fd, pointerof(pidp)) == 0
          pidp.to_i64
        else
          nil
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Block until the child exits and return its `Process::Status`. When
    # `timeout` is given and elapses first, returns `nil` and leaves the
    # child running. Implemented via `kqueue` + `EVFILT_PROCDESC` /
    # `NOTE_EXIT` — usable from inside capability mode (kqueue is allowed
    # in cap mode, and process descriptors don't need the PID namespace).
    #
    # The call yields the OS thread cooperatively via `Fiber.syscall`, so it
    # plays nicely with Crystal's scheduler. After this returns successfully
    # the child has already been reaped; closing the descriptor afterwards
    # is still safe (it's just a `close(2)`).
    def wait(timeout : Time::Span? = nil) : ::Process::Status?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!

        kq = LibC.kqueue1(0)
        raise Error.from_errno("kqueue1") if kq < 0

        begin
          changelist = LibC::Kevent.new
          changelist.ident = @fd.to_u64
          changelist.filter = LibPdfork::Kq::EVFILT_PROCDESC
          changelist.flags = LibC::EV_ADD | LibC::EV_ONESHOT
          changelist.fflags = LibPdfork::Kq::NOTE_EXIT

          if LibC.kevent(kq, pointerof(changelist), 1, nil, 0, nil) < 0
            raise Error.from_errno("kevent register")
          end

          eventlist = LibC::Kevent.new
          ts_ptr = Pointer(LibC::Timespec).null
          ts = LibC::Timespec.new
          if timeout
            total_ns = timeout.total_nanoseconds.to_i64
            ts.tv_sec = LibC::TimeT.new(total_ns // 1_000_000_000)
            ts.tv_nsec = (total_ns.remainder(1_000_000_000))
            ts_ptr = pointerof(ts)
          end

          n = FreeBSD::Capsicum.syscall { LibC.kevent(kq, nil, 0, pointerof(eventlist), 1, ts_ptr) }
          case n
          when -1
            raise Error.from_errno("kevent wait")
          when 0
            nil
          else
            ::Process::Status.new(eventlist.data.to_i32)
          end
        ensure
          LibC.close(kq)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Close the process descriptor. Without the `daemon: true` flag at
    # creation time, this sends `SIGKILL` to the child if it is still running
    # and reaps it; the kernel guarantees no zombie is left behind.
    def close : Nil
      return if @closed
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibC.close(@fd)
      {% end %}
      @closed = true
    end

    # True if the process descriptor has been closed.
    def closed? : Bool
      @closed
    end

    # Returns the raw fd number. Safe to pass to `cap_rights_limit` or kqueue.
    def to_unsafe : Int32
      @fd
    end

    # Close on GC. Important: this can race with the child's natural lifetime
    # and (without `daemon: true`) will SIGKILL a child that is still running.
    # Prefer an explicit `#close` to make the lifetime visible.
    def finalize
      close
    end

    private def check_open!
      raise Error.new("process descriptor is closed") if @closed
    end
  end

  # Fork a child via `pdfork(2)`. In the child the block runs and its return
  # value (an `Int32`) becomes the process exit code; the block never returns.
  # In the parent, returns a `ProcessDescriptor` controlling the child.
  #
  # When `daemon` is true the descriptor will NOT signal-kill the child on
  # close, mirroring `PD_DAEMON`. When `cloexec` is true the descriptor is
  # `O_CLOEXEC` (`PD_CLOEXEC`).
  def self.pdfork(daemon : Bool = false,
                  cloexec : Bool = false,
                  & : -> Int32) : ProcessDescriptor
    {% raise("pdfork is unsupported with multithreaded mode") if flag?(:preview_mt) %}
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      flags = 0
      flags |= LibPdfork::PD_DAEMON if daemon
      flags |= LibPdfork::PD_CLOEXEC if cloexec

      # Mirror the safety wrappers Crystal's own Process.fork uses internally:
      #
      #   1. pthread_setcancelstate — prevent async thread cancellation during
      #      the fork window, which would leave the process in an inconsistent
      #      state.
      #   2. block_signals — block all signals (except the GC stop-the-world
      #      pair) so the child cannot relay parent-bound signals through the
      #      signal pipe before its own handlers are in place.
      #   3. after_fork_child_callbacks — reinitialize Crystal's event loop,
      #      signal handlers, and RNG seeds in the child; equivalent to what
      #      the stdlib does after LibC.fork.
      #
      # Note: lock_write from the stdlib guards platforms without O_CLOEXEC /
      # dup3 / accept4 against fd-leak races during concurrent exec. FreeBSD
      # has had all of those since 8.x, so the lock is a no-op there and we
      # omit it.
      LibC.pthread_setcancelstate(LibC::PTHREAD_CANCEL_DISABLE, out cancel_state)

      newmask = uninitialized LibC::SigsetT
      oldmask = uninitialized LibC::SigsetT
      LibC.sigfillset(pointerof(newmask))
      # Keep the GC's stop-the-world signals unblocked — masking them causes
      # deadlocks (same reasoning as in Crystal's own block_signals helper).
      LibC.sigdelset(pointerof(newmask), GC.sig_suspend.value)
      LibC.sigdelset(pointerof(newmask), GC.sig_resume.value)
      LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(newmask), pointerof(oldmask))

      fd = 0
      pid = LibPdfork.pdfork(pointerof(fd), flags)
      # Capture errno before any other syscall can clobber it.
      saved_errno = Errno.value

      # Restore signal mask and cancellation state in the parent immediately
      # after the fork. The child resets its own mask via after_fork_child_callbacks.
      if pid != 0
        LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(oldmask), nil)
        LibC.pthread_setcancelstate(cancel_state, nil)
      end

      case pid
      when -1
        Errno.value = saved_errno
        raise Error.from_errno("pdfork")
      when 0
        status = begin
          ::Process.after_fork_child_callbacks.each(&.call)
          yield
        rescue ex
          STDERR.puts "freebsd/capsicum pdfork child:"
          ex.inspect_with_backtrace(STDERR)
          STDERR.flush
          1
        end
        exit(status)
      else
        ProcessDescriptor.new(fd, pid.to_i64)
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end
end
