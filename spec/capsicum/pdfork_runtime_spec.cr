require "../spec_helper"

# Regression: a pdfork child that starts the Crystal runtime via `previous_def`
# must not crash. pdfork previously ran `Process.after_fork_child_callbacks` in
# the child before the runtime existed, segfaulting in
# `Crystal::EventLoop.current.after_fork`. The parent always exited 0, so the
# only visible symptom was a child core dump — assert there is none.
describe "FreeBSD::Capsicum.pdfork child runtime startup" do
  it_on_capsicum "does not crash when the child calls previous_def (no core dump)" do
    fixture = File.join(__DIR__, "fixtures", "pdfork_runtime_child.cr")
    bin = File.tempname("pdfork_runtime", "")
    begin
      build = Process.run("crystal", ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      # Run in the fixture's own dir so a core file (if any) lands predictably.
      workdir = File.dirname(bin)
      captured = IO::Memory.new
      status = Process.run(bin, output: captured, error: Process::Redirect::Inherit, chdir: workdir)

      # Parent must exit cleanly...
      status.success?.should be_true
      captured.to_s.should contain("parent-ran")
      captured.to_s.should contain("child-ran")

      # ...and no process (parent or pdfork child) may have dumped core.
      Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core")).should be_empty
      Dir.glob(File.join(workdir, "*.core")).each { |f| File.delete(f) rescue nil }
    ensure
      File.delete(bin) rescue nil
    end
  end
end
