# Bindings for the Capsicum process-descriptor syscalls. Lives in libc on
# FreeBSD; declared separately so the rest of the shard's lib bindings stay
# self-describing.

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("c")]
  lib LibPdfork
    # pdfork(2) flags
    PD_DAEMON  = 0x01
    PD_CLOEXEC = 0x02

    fun pdfork(fdp : Int32*, flags : Int32) : LibC::PidT
    fun pdgetpid(fd : Int32, pidp : LibC::PidT*) : Int32
    fun pdkill(fd : Int32, signum : Int32) : Int32
  end

  # Kqueue filter / flag values not exposed by Crystal's `LibC` bindings.
  # `EVFILT_PROCDESC` + `NOTE_EXIT` is the path to wait on a process
  # descriptor — there is no dedicated `pdwait(2)` syscall on FreeBSD.
  module LibPdfork::Kq
    EVFILT_PROCDESC =         -8_i16
    NOTE_EXIT       = 0x80000000_u32
  end
{% end %}
