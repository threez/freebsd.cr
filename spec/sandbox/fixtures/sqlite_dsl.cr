# Fixture for the FreeBSD::Sandbox.define `sqlite` directive.
#
# Declares one `sqlite` directive (which opens the db directory with
# SQLITE_WAL_RIGHTS, registers it, and installs the openat VFS override), then —
# fully sandboxed (capability mode) — opens a WAL database beneath it and does a
# read+write round-trip. Proves the directive wires the VFS so the lazily-created
# -wal/-shm sidecars are opened via openat under cap_enter.
#
#   DB_DIR — directory holding the database (seeded empty by the spec)
#
# No privilege drop, so the fixture runs without root.

require "db"
require "sqlite3"

require "../../../src/freebsd/sandbox"
require "../../../src/freebsd/capsicum/integrate/sqlite"

DB_DIR  = ENV["DB_DIR"]
DB_PATH = File.join(DB_DIR, "app.db")

FreeBSD::Sandbox.define do
  sqlite "db", DB_DIR
end

# ---- sandboxed body ----

dir = FreeBSD::Sandbox.db # => FreeBSD::Capsicum::Directory
STDOUT.puts(dir.is_a?(FreeBSD::Capsicum::Directory) ? "dir-ok" : "dir-ERROR")
STDOUT.puts "sandboxed #{FreeBSD::Capsicum.sandboxed?}"

DB.open("sqlite3://#{DB_PATH}") do |db|
  STDOUT.puts "journal #{db.scalar("PRAGMA journal_mode=WAL").as(String).downcase}"
  db.exec "CREATE TABLE t (id INTEGER PRIMARY KEY, msg TEXT)"
  db.exec "INSERT INTO t (msg) VALUES (?)", "via-directive"
  STDOUT.puts "rows #{db.scalar("SELECT count(*) FROM t").as(Int64)}"
  STDOUT.puts "read #{db.query_one("SELECT msg FROM t WHERE id = 1", as: String)}"

  # The WAL sidecars exist beneath the dir fd while the connection is open.
  sidecars = dir.children(".").select(&.starts_with?("app.db")).sort!
  STDOUT.puts "files #{sidecars.join(",")}"
end

STDOUT.puts "done"
STDOUT.flush
