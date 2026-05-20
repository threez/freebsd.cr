# Transparent `File` integration.
#
# `require "freebsd/casper/integrate/file"` reopens `Crystal::System::File` and routes
# operations on paths that were declared at `Casper::Service::FileArgs`
# creation time through the Casper helper:
#
# * `File.open` / `File.read` / `File.each_line` …  ⇒  `fileargs_open`
# * `File.info` / `File.info?`                       ⇒  `fileargs_lstat`
# * `File.exists?`                                   ⇒  `fileargs_lstat` (success)
# * `File.real_path` (and `Path.expand` family)      ⇒  `fileargs_realpath`
#
# Undeclared paths fall through to libc, so the require is safe to load
# unconditionally. Operations beyond open/lstat/realpath also require the
# corresponding `fa_flags` (`OPEN`, `LSTAT`, `REALPATH`) at FileArgs creation;
# if a path is declared but the helper wasn't granted that op, the libcap
# call returns an error and we raise `File::Error` rather than silently
# falling through.
#
# Caveats — path matching is *exact-string*:
#
# * `"/etc/hosts"` and `"./etc/hosts"` are different.
# * Symlinks and `..` aren't resolved by the lookup; declare the form your
#   code uses.
# * `info?(follow_symlinks: true)` is downgraded to `lstat` for declared
#   paths (fileargs only exposes `lstat`); if the declared path is a
#   symlink, this is observably different from libc behavior.
# * `Dir.glob`, `Dir.entries`, and other directory operations are *not*
#   hooked — fileargs is single-path, not directory-listing.

require "../fileargs"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module Crystal::System::File
    def self.open(filename : String,
                  mode : String,
                  perm : Int32 | ::File::Permissions,
                  blocking : Bool?) : {FileDescriptor::Handle, Bool}
      if (fa = FreeBSD::Casper.fileargs?) && fa.declared?(filename)
        fd = fa.open_fd(filename)
        {fd, blocking != false}
      else
        previous_def
      end
    end

    def self.info?(path : String, follow_symlinks : Bool) : ::File::Info?
      if (fa = FreeBSD::Casper.fileargs?) && fa.declared?(path)
        fa.lstat(path)
      else
        previous_def
      end
    end

    def self.exists?(path)
      if (fa = FreeBSD::Casper.fileargs?) && fa.declared?(path)
        !fa.lstat(path).nil?
      else
        previous_def
      end
    end

    def self.realpath(path)
      if (fa = FreeBSD::Casper.fileargs?) && fa.declared?(path)
        fa.realpath(path)
      else
        previous_def
      end
    end
  end
{% end %}
