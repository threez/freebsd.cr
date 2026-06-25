# Fixture for the FreeBSD::Sandbox.define `directory` directive.
#
# Declares one single-path `directory` and one array-form `directory`, then —
# fully sandboxed (capability mode) — opens files beneath them. The single form
# exercises both the explicit `Sandbox.<name>.open` API and transparent
# `File.open` routing (via `capsicum/integrate/file`); the array form proves the
# accessor is an `Array(Directory)` and that every base is registered for
# routing.
#
# Directory paths come from the environment so the driving spec can point them at
# tmpdirs it has seeded:
#   WWWROOT  — single served directory (contains page.html)
#   TREE_A   — first array directory (contains a.txt)
#   TREE_B   — second array directory (contains b.txt)
#
# No privilege drop, so the fixture runs without root.

require "../../../src/freebsd/sandbox"
require "../../../src/freebsd/capsicum/integrate/file"

WWWROOT = ENV["WWWROOT"]
TREE_A  = ENV["TREE_A"]
TREE_B  = ENV["TREE_B"]

FreeBSD::Sandbox.define do
  directory "wwwroot", WWWROOT, rights: [:lookup, :read, :fstat]
  directory "trees", [TREE_A, TREE_B]
end

# ---- sandboxed body ----

www = FreeBSD::Sandbox.wwwroot # => FreeBSD::Capsicum::Directory
STDOUT.puts(www.is_a?(FreeBSD::Capsicum::Directory) ? "single-ok" : "single-ERROR")

# Explicit openat under the single directory.
www.open("page.html") { |f| STDOUT.puts "explicit #{f.gets_to_end}" }

# Transparent routing: File.open of a path beneath the registered base.
STDOUT.puts "routed #{File.read(File.join(WWWROOT, "page.html"))}"

trees = FreeBSD::Sandbox.trees # => Array(FreeBSD::Capsicum::Directory)
STDOUT.puts "trees #{trees.size}"

# Routing works under either array directory.
STDOUT.puts "tree-a #{File.read(File.join(TREE_A, "a.txt"))}"
STDOUT.puts "tree-b #{File.read(File.join(TREE_B, "b.txt"))}"

# Direct access outside any registered base is blocked by capability mode.
begin
  File.read("/etc/passwd")
  STDOUT.puts "passwd-open-ERROR"
rescue File::Error
  STDOUT.puts "passwd-blocked"
end

STDOUT.puts "done"
STDOUT.flush
