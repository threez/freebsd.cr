# Child-side runtime re-initialisation after a raw `pdfork`.
#
# Crystal <= 1.21 (under `-D without_mt`) ran `Process.after_fork_child_callbacks`
# to rebuild the event loop in a forked child. Crystal 1.22 removed that hook
# (and `Process.fork`), but a kqueue is not inherited across fork(2) on FreeBSD,
# so the child still has to rebuild it by hand or `sleep`, timers and
# non-blocking IO break.
{% if flag?(:without_mt) && (flag?(:freebsd) || flag?(:dragonfly)) && compare_versions(Crystal::VERSION, "1.22.0") >= 0 %}
  class Crystal::EventLoop::Kqueue
    # :nodoc:
    # Re-creates the kqueue in a forked child and re-registers every
    # descriptor (and the pending timer) the inherited event loop knew about.
    def freebsd_after_fork : Nil
      @kqueue = Crystal::System::Kqueue.new
      @interrupted.set(false)
      @kqueue.kevent(
        INTERRUPT_IDENTIFIER,
        LibC::EVFILT_USER,
        LibC::EV_ADD | LibC::EV_ENABLE | LibC::EV_CLEAR)
      Crystal::EventLoop::Polling.arena.each_index do |fd, index|
        system_add(fd, index)
      end
      system_set_timer(@timers.next_ready?)
    end
  end
{% end %}

module FreeBSD::Capsicum
  # :nodoc:
  # Runs in a `pdfork`'d child that continues executing Crystal code, but only
  # when a live event loop exists (see `Capsicum.pdfork`).
  def self.after_fork_child : Nil
    {% if compare_versions(Crystal::VERSION, "1.22.0") < 0 %}
      Process.after_fork_child_callbacks.each(&.call)
    {% elsif flag?(:without_mt) && (flag?(:freebsd) || flag?(:dragonfly)) %}
      if loop = Crystal::EventLoop.current?
        loop.as(Crystal::EventLoop::Kqueue).freebsd_after_fork
      end
    {% end %}
  end
end
