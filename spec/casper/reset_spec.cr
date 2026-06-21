require "../spec_helper"
require "../../src/freebsd/casper/net"

# Unit coverage for the reset-hook registry that lets a pdfork helper child drop
# Casper service handles it inherited from the parent. See the end-to-end
# fixture spec below for the integration-level guarantee.
describe "FreeBSD::Casper.reset!" do
  it "is a no-op (and does not raise) when no hook is registered" do
    # reset! must be safe to call even before any register_* ran / pre-runtime.
    FreeBSD::Casper.reset!
  end

  it "runs every registered hook" do
    fired = 0
    FreeBSD::Casper.on_reset { fired += 1 }
    FreeBSD::Casper.on_reset { fired += 1 }
    before = fired
    FreeBSD::Casper.reset!
    (fired - before).should be >= 2
  end
end

# End-to-end smoke test: combining register_audit_helper + register_net must
# start cleanly with no child core dump. This guards the pre-runtime safety of
# the reset machinery — `reset!` is invoked from the audit pdfork child's
# main_user_code (pre-runtime) and must not SIGSEGV (the v15.0.4 registry did,
# by iterating an uninitialised class var). Note: the audit child normally exits
# at the `is_helper` guard before the app body, so this asserts "starts without
# crashing", not a red/green reproduction of the inherited-channel deadlock.
describe "register_audit_helper + register_net pdfork child" do
  it_on_capsicum "starts without a child core dump" do
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
      captured.to_s.should contain("done")
      # FreeBSD's default corefile is "%N.core" (program basename) in the cwd.
      # Scope to this binary's name so unrelated cores in the temp dir don't fail us.
      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      File.delete(bin) rescue nil
    end
  end
end
