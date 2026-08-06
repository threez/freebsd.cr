require "../spec_helper"

# Drives spec/sandbox/fixtures/standalone_prime_dsl.cr: builds it, runs it (no
# privilege drop needed — this doesn't touch Sandbox.define/cap_enter at all),
# and checks that FreeBSD::Sandbox.prime_tz_data!/.prime_tls_context! work
# called directly, and that calling either twice is a safe no-op.
describe "FreeBSD::Sandbox standalone priming (.prime_tz_data! / .prime_tls_context!)" do
  it "works without any Sandbox.define call, and priming twice is a no-op" do
    fixture = File.join(__DIR__, "fixtures", "standalone_prime_dsl.cr")
    bin = File.tempname("standalone_prime", "")
    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      out_io = IO::Memory.new
      status = Process.run(bin, output: out_io, error: Process::Redirect::Inherit)
      out = out_io.to_s
      status.success?.should be_true

      out.should contain("builder-ok")
      out.should contain("tz-ok")
      out.should contain("done")
    ensure
      File.delete(bin) rescue nil
    end
  end
end
