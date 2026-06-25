# Transparent `File.open` routing for registered `Directory` handles.
#
# `require "freebsd/capsicum/integrate/file"` reopens `Crystal::System::File.open`
# and routes any path that lives beneath a registered directory's base
# (see `FreeBSD::Capsicum.register_directory`) through that directory's
# `openat(2)` — the only in-process way to open a file once `cap_enter` has run.
#
# ```
# require "freebsd/capsicum/integrate/file"
#
# dir = FreeBSD::Capsicum::Directory.open("/var/www", rights: [:lookup, :read, :fstat])
# FreeBSD::Capsicum.register_directory(dir)
# FreeBSD::Capsicum.sandbox!
# File.read("/var/www/index.html") # works — routed through openat under dir.fd
# File.read("/etc/passwd")         # raises (ECAPMODE) — not under any base
# ```
#
# Paths not beneath any registered base fall through to libc, so the require is
# safe to load unconditionally. When the Casper `fileargs` integration is also
# required, the two reopens chain via `previous_def`; require *this* file after
# the casper one for precedence: directory registry -> fileargs -> libc.
#
# `File.open`, `File.info?` / `File.info`, and `File.exists?` are hooked (the
# latter two via `fstatat`/`faccessat` under the dir fd). `File.real_path` is
# **not** routed — `realpath(3)` has no `*at` form usable beneath a dir fd, so
# paths beneath a registered base fall through to libc and raise `ECAPMODE` in
# the sandbox, same as any unhooked op. For directory *listing*
# (`Dir.entries`/`glob`/…) require `freebsd/capsicum/integrate/dir`.

require "../directory"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module Crystal::System::File
    def self.open(filename : String,
                  mode : String,
                  perm : Int32 | ::File::Permissions,
                  blocking : Bool?) : {FileDescriptor::Handle, Bool}
      if match = FreeBSD::Capsicum.directory_for(filename)
        dir, rel = match
        perm_int = perm.is_a?(::File::Permissions) ? perm.value : perm
        {dir.open_fd(rel, mode, perm_int), blocking != false}
      else
        previous_def
      end
    end

    def self.info?(path : String, follow_symlinks : Bool) : ::File::Info?
      if match = FreeBSD::Capsicum.directory_for(path)
        dir, rel = match
        dir.info?(rel, follow_symlinks)
      else
        previous_def
      end
    end

    def self.exists?(path)
      if match = FreeBSD::Capsicum.directory_for(path)
        dir, rel = match
        dir.exists?(rel)
      else
        previous_def
      end
    end
  end
{% end %}
