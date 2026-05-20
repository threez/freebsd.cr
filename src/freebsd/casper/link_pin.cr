# :nodoc:
# Promote `libcasper.so` into the global dynamic-linker namespace at
# require time via `dlopen(RTLD_GLOBAL)`.
#
# Each `libcap_*.so` (dns, pwd, grp, …) has a load-time constructor that
# calls `service_register` from `libcasper.so`. That symbol must already
# be in the *global* namespace when the libcap_*.so is loaded — but the
# static `-lcasper` link flag alone does not make symbols RTLD_GLOBAL;
# it only ensures the library appears in the binary's DT_NEEDED list.
#
# Solution: dlopen `libcasper.so` with RTLD_GLOBAL once here, before any
# service library is loaded. Each service's own `@[Link("cap_xxx")]`
# annotation pulls in its `.so` via the normal static linker path.
#
# `dlopen(3)` is opaque to LLVM so this call cannot be optimised away.
# It lives at file scope so it runs at `require` time, not lazily.

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  # Force `-lcasper` into the link line. Without this declaration Crystal's
  # dead-code eliminator may drop the `-lcasper` flag when no `LibCasper`
  # symbol is reachable from user code, causing `libcap_*.so` loads to fail
  # at binary launch because their DT_NEEDED on `libcasper.so` can't resolve
  # `service_register`.
  @[Link("casper")]
  lib LibCasperPin
    fun cap_sandboxed : Bool
  end

  # Top-level call so the reference to LibCasperPin is not dead-code eliminated.
  LibCasperPin.cap_sandboxed

  # Promote libcasper into the global namespace so service_register is
  # visible to every subsequent libcap_*.so constructor.
  _handle = LibC.dlopen("libcasper.so", LibC::RTLD_NOW | LibC::RTLD_GLOBAL)
  if _handle.null?
    _err = LibC.dlerror
    _msg = _err.null? ? "(unknown error)" : String.new(_err)
    raise FreeBSD::Capsicum::Error.new("cannot dlopen libcasper.so: #{_msg}")
  end
{% end %}
