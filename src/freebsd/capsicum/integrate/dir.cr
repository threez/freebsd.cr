# Transparent directory-listing routing for registered `Directory` handles.
#
# `require "freebsd/capsicum/integrate/dir"` reopens `Crystal::System::Dir.open`
# so that `Dir.entries`, `Dir.children`, `Dir.each_child`, and
# `Dir.new(path).each` of any path beneath (or equal to) a registered
# directory's base are served from that directory's fd via `fdopendir(2)` — the
# only in-process way to list a directory once `cap_enter` has run.
#
# ```
# require "freebsd/capsicum/integrate/dir"
#
# dir = FreeBSD::Capsicum::Directory.open("/var/www", rights: [:lookup, :read, :fstat])
# FreeBSD::Capsicum.register_directory(dir)
# FreeBSD::Capsicum.sandbox!
# Dir.children("/var/www") # works — fdopendir under dir.fd
# Dir.each_child("/var/www") { |n| ... }
# ```
#
# Only `Crystal::System::Dir.open` is reopened; `next_entry`/`info`/`rewind`/
# `close` operate on the returned `DIR*` and need no override. Paths not beneath
# any registered base fall through to libc (and raise `ECAPMODE` in the sandbox).
#
# `Dir.glob` is **not** supported in the sandbox: its algorithm calls
# `Dir.current` (`getcwd(2)`) internally to resolve the filesystem root, which is
# forbidden in capability mode — independent of this routing. Use
# `FreeBSD::Capsicum::Directory#children`/`#each_child` (or `Dir.children`) and
# filter names yourself instead.
#
# Listing needs `:read` + `:lookup` + `:fstat` on the directory fd — the default
# `directory` rights (`[:lookup, :read, :fstat]`) provide all three. A directory
# opened without `:read` (e.g. a write-only drop) cannot be listed.

require "../directory"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module Crystal::System::Dir
    def self.open(path : String) : LibC::DIR*
      if match = FreeBSD::Capsicum.directory_or_base_for(path)
        dir, rel = match
        dir.opendir_at(rel)
      else
        previous_def
      end
    end
  end
{% end %}
