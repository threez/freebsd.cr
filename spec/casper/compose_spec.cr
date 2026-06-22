require "../spec_helper"

# Compose test: `register_audit_helper` (pre-runtime pdfork) + `register_net`
# (C-style top-level install). The audit pdfork child must not run any service
# setup / `cap_init` — that is what the old `main_user_code` cascade got wrong.
# The parent always exits 0, so the meaningful checks are: parent exits 0, the
# net service is installed, and no process (parent or helper child) dumped core.
describe "register_audit_helper + register_net compose" do
  it_on_capsicum "installs net and starts without a child core dump" do
    fixture = File.join(__DIR__, "fixtures", "audit_net_resolve.cr")
    bin = File.tempname("audit_net_resolve", "")
    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      workdir = File.dirname(bin)
      captured = IO::Memory.new
      status = Process.run(bin, output: captured, error: Process::Redirect::Inherit, chdir: workdir)

      status.success?.should be_true
      captured.to_s.should contain("net-installed")
      captured.to_s.should contain("done")

      # FreeBSD's default corefile is "%N.core" (program basename) in the cwd.
      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      File.delete(bin) rescue nil
    end
  end
end
