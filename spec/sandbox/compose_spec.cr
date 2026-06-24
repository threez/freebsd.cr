require "../spec_helper"

# Compose test for FreeBSD::Sandbox.define: a pre-runtime pdfork helper
# (audit_helper) + a C-style net service + a rights-limited `open` resource + a
# privileged `bind` listener + cap_enter, all from one declaration.
#
# Checks: parent exits 0; net service installed; the read-only opened file reads
# but rejects writes (cap_rights_limit enforced); the default listener rights
# permit `accept` inside the sandbox; direct file access is blocked; and no
# process (parent or helper child) dumped core (the EDEADLK signature the single
# helper-child guard prevents).
describe "FreeBSD::Sandbox.define compose" do
  it_on_capsicum "sets up helper + net + rights-limited resources and sandboxes cleanly" do
    fixture = File.join(__DIR__, "fixtures", "compose.cr")
    bin = File.tempname("sandbox_compose", "")
    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      workdir = File.dirname(bin)
      reader, writer = IO.pipe
      process = Process.new(bin, output: writer, error: Process::Redirect::Inherit, chdir: workdir)
      writer.close

      lines = [] of String
      # Read line by line; when the fixture announces its listener, connect to
      # it from here (unsandboxed) so its in-sandbox `accept` returns.
      while line = reader.gets
        lines << line
        if line.starts_with?("listen ")
          _, host, port = line.split(' ')
          TCPSocket.new(host, port.to_i).close
        end
        break if line == "done"
      end
      reader.close
      process.wait.success?.should be_true

      out = lines.join('\n')
      out.should contain("net-installed")
      out.should contain("ro-readable")
      out.should contain("ro-write-blocked")
      out.should contain("passwd-blocked")
      out.should contain("accept-ok")
      out.should contain("done")

      # FreeBSD's default corefile is "%N.core" (program basename) in the cwd.
      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      File.delete(bin) rescue nil
    end
  end
end
