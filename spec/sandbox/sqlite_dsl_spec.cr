require "../spec_helper"
require "file_utils"

# Drives spec/sandbox/fixtures/sqlite_dsl.cr: builds it, seeds an empty db dir,
# runs it, and checks that the `sqlite` directive opens+registers the dir and
# installs the VFS override so a WAL database reads and writes via openat inside
# the sandbox.
describe "FreeBSD::Sandbox.define sqlite directive" do
  it_on_capsicum "runs a WAL read+write round-trip via openat inside the sandbox" do
    fixture = File.join(__DIR__, "fixtures", "sqlite_dsl.cr")
    bin = File.tempname("sandbox_sqlite", "")
    db_dir = File.tempname("sqlite_dsl", "")
    Dir.mkdir(db_dir)

    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      env = {"DB_DIR" => db_dir}
      workdir = File.dirname(bin)
      reader, writer = IO.pipe
      process = Process.new(bin, env: env, output: writer,
        error: Process::Redirect::Inherit, chdir: workdir)
      writer.close
      out = reader.gets_to_end
      reader.close
      process.wait.success?.should be_true

      out.should contain("dir-ok")
      out.should contain("sandboxed true")
      out.should contain("journal wal")
      out.should contain("rows 1")
      out.should contain("read via-directive")
      out.should contain("files app.db,app.db-shm,app.db-wal")
      out.should contain("done")

      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      File.delete(bin) rescue nil
      FileUtils.rm_rf(db_dir) rescue nil
    end
  end
end
