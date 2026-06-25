require "../spec_helper"
require "file_utils"

# Drives spec/sandbox/fixtures/directory_dsl.cr: builds it, seeds three tmpdirs,
# runs it, and checks that the `directory` directive's single- and array-path
# forms expose the right accessors AND route File.open through openat inside the
# sandbox.
describe "FreeBSD::Sandbox.define directory directive" do
  it_on_capsicum "opens files beneath pre-opened directories via openat (single + array)" do
    fixture = File.join(__DIR__, "fixtures", "directory_dsl.cr")
    bin = File.tempname("sandbox_directory", "")
    wwwroot = File.tempname("wwwroot", "")
    tree_a = File.tempname("tree_a", "")
    tree_b = File.tempname("tree_b", "")
    [wwwroot, tree_a, tree_b].each { |d| Dir.mkdir(d) }
    File.write(File.join(wwwroot, "page.html"), "PAGE")
    File.write(File.join(tree_a, "a.txt"), "AAA")
    File.write(File.join(tree_b, "b.txt"), "BBB")

    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      env = {"WWWROOT" => wwwroot, "TREE_A" => tree_a, "TREE_B" => tree_b}
      workdir = File.dirname(bin)
      reader, writer = IO.pipe
      process = Process.new(bin, env: env, output: writer,
        error: Process::Redirect::Inherit, chdir: workdir)
      writer.close
      out = reader.gets_to_end
      reader.close
      process.wait.success?.should be_true

      out.should contain("single-ok")
      out.should contain("explicit PAGE")
      out.should contain("routed PAGE")
      out.should contain("trees 2")
      out.should contain("tree-a AAA")
      out.should contain("tree-b BBB")
      out.should contain("passwd-blocked")
      out.should contain("done")

      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      File.delete(bin) rescue nil
      [wwwroot, tree_a, tree_b].each { |d| FileUtils.rm_rf(d) rescue nil }
    end
  end
end
