require "../../spec_helper"
require "../../../src/freebsd/capsicum/integrate/sqlite"
require "db"
require "sqlite3"
require "file_utils"

private def with_tmpdir(&)
  dir = File.tempname("capsqlite", "")
  Dir.mkdir(dir)
  begin
    yield dir
  ensure
    FileUtils.rm_rf(dir) rescue nil
  end
end

describe "FreeBSD::Capsicum sqlite VFS integration" do
  describe ".directory_for routing (no sandbox)" do
    it_on_capsicum "maps a db path and its WAL sidecars beneath a registered base" do
      with_tmpdir do |tmp|
        dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
        FreeBSD::Capsicum.register_directory(dir)
        begin
          # The main db and the -wal/-shm sidecars are all strictly beneath the
          # base, so each resolves to {dir, relative-name}.
          {"app.db", "app.db-wal", "app.db-shm"}.each do |name|
            match = FreeBSD::Capsicum.directory_for(File.join(tmp, name))
            match.should_not be_nil
            d, rel = match.not_nil!
            d.base.should eq(dir.base)
            rel.should eq(name)
          end

          # A path outside the base does not match; a relative path is not routed.
          FreeBSD::Capsicum.directory_for("/tmp/elsewhere.db").should be_nil
          FreeBSD::Capsicum.directory_for("app.db").should be_nil
        ensure
          FreeBSD::Capsicum.unregister_directory(dir)
          dir.close
        end
      end
    end

    it_on_capsicum "register_sqlite_dir registers the dir with the WAL rights" do
      with_tmpdir do |tmp|
        dir = FreeBSD::Capsicum.register_sqlite_dir(tmp)
        begin
          # It is registered: a db path beneath it now resolves for routing.
          match = FreeBSD::Capsicum.directory_for(File.join(tmp, "app.db"))
          match.should_not be_nil
          match.not_nil![0].base.should eq(dir.base)

          # And the fd carries the full WAL rights set (incl. the easily-missed
          # :fsync), so a sandboxed WAL db would not hit "disk I/O error".
          rights = dir.rights
          FreeBSD::Capsicum::SQLITE_WAL_RIGHTS.each do |r|
            rights.includes?(r).should be_true
          end
        ensure
          FreeBSD::Capsicum.unregister_directory(dir)
          dir.close
        end
      end
    end
  end

  describe "WAL read+write inside the sandbox" do
    it_on_capsicum "creates -wal/-shm and round-trips rows via openat after cap_enter" do
      with_tmpdir do |tmp|
        db_path = File.join(tmp, "app.db")
        in_sandbox_child do
          # register_sqlite_dir bundles Directory.open(SQLITE_WAL_RIGHTS) +
          # register_directory + install_sqlite_vfs_openat.
          dir = FreeBSD::Capsicum.register_sqlite_dir(tmp)
          FreeBSD::Capsicum.sandbox!

          DB.open("sqlite3://#{db_path}") do |db|
            db.scalar("PRAGMA journal_mode=WAL").as(String).downcase.should eq("wal")
            db.exec "CREATE TABLE t (id INTEGER PRIMARY KEY, msg TEXT)"
            db.exec "INSERT INTO t (msg) VALUES (?)", "sandboxed"
            db.exec "INSERT INTO t (msg) VALUES (?)", "openat"

            db.scalar("SELECT count(*) FROM t").as(Int64).should eq(2)
            db.query_one("SELECT msg FROM t WHERE id = 1", as: String).should eq("sandboxed")

            # While the connection is open the WAL sidecars exist beneath the dir
            # fd — created via openat under cap_enter (listed via fdopendir). They
            # are checkpointed away (unlinkat) on a clean close, so we check here.
            names = dir.children(".")
            names.should contain("app.db")
            names.should contain("app.db-wal")
            names.should contain("app.db-shm")
          end

          # After a clean close SQLite checkpoints and removes the sidecars; only
          # the main db remains. That the -wal/-shm were unlinked exercises the
          # unlinkat override too.
          dir.children(".").should eq(["app.db"])
        end
      end
    end

    it_on_capsicum "denies a database outside the registered directory" do
      with_tmpdir do |tmp|
        outside = File.join(tmp, "real", "app.db")
        Dir.mkdir(File.join(tmp, "real"))
        # Register a *different* directory so `outside` matches no base.
        registered = File.join(tmp, "box")
        Dir.mkdir(registered)
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(registered,
            rights: [:lookup, :read, :write, :create, :fstat, :fcntl,
                     :seek, :flock, :mmap, :fsync, :ftruncate, :unlinkat])
          FreeBSD::Capsicum.register_directory(dir)
          FreeBSD::Capsicum.install_sqlite_vfs_openat
          FreeBSD::Capsicum.sandbox!

          # Opening a db not beneath any registered base falls through to open(2),
          # which capability mode forbids — SQLite surfaces it as an error.
          expect_raises(Exception) do
            DB.open("sqlite3://#{outside}") do |db|
              db.exec "CREATE TABLE t (x INTEGER)"
            end
          end
        end
      end
    end
  end
end
