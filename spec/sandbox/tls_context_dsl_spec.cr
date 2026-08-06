require "../spec_helper"
require "http/client"
require "http/server"

# Drives spec/sandbox/fixtures/tls_context_dsl.cr: builds it, stands up a
# plaintext echo upstream, runs the fixture, and checks that the
# `tls_context` directive's accessor and `.http_client_builder` are usable
# once the fixture is fully sandboxed (capability mode) — i.e. that an
# HTTP::Client built post-cap_enter from a context primed pre-cap_enter still
# behaves like a normal client.
describe "FreeBSD::Sandbox.define tls_context directive" do
  it_on_capsicum "builds a working HTTP::Client from a context primed before cap_enter" do
    upstream = HTTP::Server.new do |ctx|
      ctx.response.content_type = "text/plain"
      ctx.response.print "echo #{ctx.request.method} #{ctx.request.path}"
    end
    up_addr = upstream.bind_unused_port("127.0.0.1")
    spawn { upstream.listen }

    fixture = File.join(__DIR__, "fixtures", "tls_context_dsl.cr")
    bin = File.tempname("sandbox_tls_context", "")
    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      env = {"UPSTREAM_HOST" => up_addr.address, "UPSTREAM_PORT" => up_addr.port.to_s}
      workdir = File.dirname(bin)
      reader, writer = IO.pipe
      process = Process.new(bin, env: env, output: writer,
        error: Process::Redirect::Inherit, chdir: workdir)
      writer.close
      out = reader.gets_to_end
      reader.close
      process.wait.success?.should be_true

      out.should contain("context-ok")
      out.should contain("builder-ok")
      out.should contain("status 200")
      out.should contain("body echo GET /")
      out.should contain("done")

      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      upstream.close rescue nil
      File.delete(bin) rescue nil
    end
  end
end
