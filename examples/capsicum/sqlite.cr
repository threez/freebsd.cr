# An end-to-end proof that a **WAL** SQLite database reads and writes entirely
# inside a Capsicum sandbox — in capability mode, where `open(2)` is forbidden —
# by routing `libsqlite3`'s file opens through `openat(2)` beneath a directory
# fd opened up front.
#
# ## Why this is non-trivial
#
# A WAL database is not one file. From a single connection SQLite opens, *after*
# the first transaction (i.e. already inside the sandbox):
#
#   * `app.db`       — the main database
#   * `app.db-wal`   — the write-ahead log, created on first write
#   * `app.db-shm`   — the shared-memory index, mmap'd and byte-range locked
#
# plus it fsyncs the containing directory. Each of those is opened by
# `libsqlite3` with its own `open(2)` inside the unix VFS, which never passes
# through Crystal's `File.open` — so the `integrate/file` routing does not catch
# them, and pre-opening just the main db fd is not enough.
#
# `freebsd/capsicum/integrate/sqlite` solves this by overriding the unix VFS's
# path-taking syscalls (`open`/`access`/`stat`/`lstat`/`unlink`/`openDirectory`)
# so each is redirected to its `*at` form beneath a registered `Directory` fd.
#
# ## Why it proves the sandbox
#
# Every privilege is acquired *before* `cap_enter`: the db directory fd is opened
# and rights-limited, the VFS override is installed, and only then does the
# process enter capability mode. Afterwards the program opens the database, forces
# WAL, writes rows, and reads them back — all through `openat` beneath the dir fd.
# A second probe shows a database *outside* the registered directory is
# unreachable (`open(2)`/`ECAPMODE`), proving confinement.
#
# ## Run it
#
#   mkdir -p /tmp/sqlite_box
#   crystal run examples/capsicum/sqlite.cr
#
# Expected: it reports `sandboxed? = true`, creates app.db + app.db-wal +
# app.db-shm under /tmp/sqlite_box via openat, inserts and reads rows, and prints
# the row it read back, then confirms an out-of-sandbox db path is denied.
#
# Optional: run under `ktrace -i` / `truss` and confirm the `-wal`/`-shm` files
# are opened with `openat`, not `open`.

require "db"
require "sqlite3"

require "../../src/freebsd/capsicum"
# Override libsqlite3's VFS file opens to go through openat beneath a registered
# directory fd, so WAL -wal/-shm sidecars work under cap_enter.
require "../../src/freebsd/capsicum/integrate/sqlite"

# The directory that holds the database. Opened as a directory fd before the
# sandbox is entered; nothing outside it is reachable once sandboxed.
DB_DIR  = "/tmp/sqlite_box"
DB_PATH = File.join(DB_DIR, "app.db")

# A database path *outside* the sandboxed directory, used for the negative probe.
OUTSIDE_DB = "/tmp/outside_app.db"

Dir.mkdir_p(DB_DIR)

# Pre-open the database directory as a directory fd (rights-limited to exactly
# what a read+write WAL database needs — see SQLITE_WAL_RIGHTS), register it for
# openat routing, and install the SQLite VFS override — all in one call. This
# bundles Directory.open + register_directory + install_sqlite_vfs_openat, and
# must run before cap_enter. The returned Directory lets us list the db files.
dir = FreeBSD::Capsicum.register_sqlite_dir(DB_DIR)

# ---- enter the sandbox: from here on open(2) is forbidden -------------------
FreeBSD::Capsicum.sandbox!
puts "sandboxed? = #{FreeBSD::Capsicum.sandboxed?}"

# Open the database by ABSOLUTE path (a relative path would make SQLite call
# getcwd(2), which capability mode forbids). The connection, the lazily-created
# -wal and -shm sidecars, and the directory fsync all route through openat
# beneath the registered dir fd.
DB.open("sqlite3://#{DB_PATH}") do |db|
  mode = db.scalar("PRAGMA journal_mode=WAL").as(String)
  puts "journal_mode = #{mode}" # => wal

  db.exec "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, msg TEXT)"
  db.exec "DELETE FROM events"
  db.exec "INSERT INTO events (msg) VALUES (?)", "hello from inside the sandbox"
  db.exec "INSERT INTO events (msg) VALUES (?)", "written via openat under cap_enter"

  count = db.scalar("SELECT count(*) FROM events").as(Int64)
  puts "rows written = #{count}"

  puts "rows read back:"
  db.query "SELECT id, msg FROM events ORDER BY id" do |rs|
    rs.each do
      puts "  #{rs.read(Int64)}: #{rs.read(String)}"
    end
  end

  # While the connection is open the WAL sidecars exist beneath the dir fd —
  # created via openat under cap_enter, listed via fdopendir under the same fd.
  live = dir.children(".").select(&.starts_with?("app.db")).sort!
  puts "db files while open: #{live.join(", ")}" # => app.db, app.db-shm, app.db-wal
end

# On a clean close SQLite checkpoints and unlinks the -wal/-shm sidecars (also
# routed through the openat/unlinkat overrides), leaving just the main db.
remaining = dir.children(".").select(&.starts_with?("app.db")).sort!
puts "db files after close: #{remaining.join(", ")}" # => app.db

# ---- negative probe: a db outside the registered directory is unreachable ----
print "opening a db outside the sandbox dir... "
begin
  DB.open("sqlite3://#{OUTSIDE_DB}") do |db|
    db.exec "CREATE TABLE t (x INTEGER)"
  end
  puts "UNEXPECTED: it succeeded (confinement broken!)"
rescue ex
  # SQLite surfaces the failed open as a generic error; the underlying cause is
  # ECAPMODE from open(2) on a path not beneath any registered directory.
  puts "denied as expected (#{ex.class})"
end

puts "done."
