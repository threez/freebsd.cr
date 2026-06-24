require "../spec_helper"
require "http/client"
require "http/server"

# End-to-end regression for the sandboxed HTTP proxy (the worked example in
# examples/casper/http_proxy.cr). Proves that a process built from a single
# FreeBSD::Sandbox.define block keeps serving real traffic while sandboxed:
#
#   * it serves /healthz from inside capability mode (carried listener fd works);
#   * /proxy round-trips a request to an allowlisted upstream through the Casper
#     net policy (DNS + connect to a permitted host);
#   * an un-allowlisted host is rejected with 403;
#   * each request is appended to the carried write-only log fd;
#   * /stats is answered by a *second* pdfork'd root helper (the "visits"
#     counter), proving multiple Casper helpers compose under one `define`;
#   * SIGTERM shuts it down cleanly (exit 0), and no process — parent, audit
#     helper, or visits helper — dumps core (the EDEADLK signature the single
#     helper-child guard in `define` prevents).
#
# The driver stands up an unsandboxed echo upstream in-process, passes its
# host:port to the fixture (which adds exactly that to its allowlist), connects
# to the proxy from here, and asserts the round-trip and the block.
describe "sandboxed http proxy" do
  it_on_capsicum "proxies allowlisted hosts, blocks others, and exits cleanly on SIGTERM" do
    # In-process echo upstream: reflects method + body so we can assert the
    # forwarded request arrived intact.
    upstream = HTTP::Server.new do |ctx|
      ctx.response.content_type = "text/plain"
      ctx.response.print "echo #{ctx.request.method} #{ctx.request.path}"
    end
    up_addr = upstream.bind_unused_port("127.0.0.1")
    spawn { upstream.listen }

    log = File.tempname("http_proxy_access", ".log")
    visits_file = File.tempname("http_proxy_visits", ".txt")
    fixture = File.join(__DIR__, "fixtures", "http_proxy.cr")
    bin = File.tempname("sandbox_http_proxy", "")
    begin
      build = Process.run(CRYSTAL_BIN, ["build", fixture, "-o", bin],
        output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      build.success?.should be_true

      workdir = File.dirname(bin)
      env = {
        "PROXY_LOG"     => log,
        "VISITS_FILE"   => visits_file,
        "UPSTREAM_HOST" => up_addr.address,
        "UPSTREAM_PORT" => up_addr.port.to_s,
      }
      reader, writer = IO.pipe
      process = Process.new(bin, env: env, output: writer,
        error: Process::Redirect::Inherit, chdir: workdir)
      writer.close

      # First stdout line announces the proxy's ephemeral listener address.
      first = reader.gets
      first.should_not be_nil
      first.not_nil!.starts_with?("listen ").should be_true
      _, phost, pport = first.not_nil!.split(' ')
      base = "http://#{phost}:#{pport}"

      # /healthz served from inside the sandbox.
      health = HTTP::Client.get("#{base}/healthz")
      health.status_code.should eq(200)
      health.body.should eq("ok")

      # /proxy round-trips to the allowlisted upstream.
      allowed_url = "http://#{up_addr.address}:#{up_addr.port}/hello"
      proxied = HTTP::Client.get("#{base}/proxy?url=#{URI.encode_www_form(allowed_url)}")
      proxied.status_code.should eq(200)
      proxied.body.should eq("echo GET /hello")

      # An un-allowlisted host is rejected with 403 (never reaches the network).
      blocked = HTTP::Client.get(
        "#{base}/proxy?url=#{URI.encode_www_form("http://192.0.2.1:80/x")}")
      blocked.status_code.should eq(403)

      # The carried write-only log fd received the request lines.
      File.read(log).should contain("proxy")

      # /stats is answered by the second (visits) helper — proving two pdfork'd
      # root helpers compose. The successful proxy above recorded one visit.
      stats = HTTP::Client.get("#{base}/stats")
      stats.status_code.should eq(200)
      stats.body.should contain(allowed_url)
      stats.body.should contain("1\t")
      # The visits file is owned/written by the helper, not the main process.
      File.read(visits_file).should contain(allowed_url)

      # SIGTERM → clean shutdown.
      process.signal(Signal::TERM)
      drained = reader.gets_to_end # let the body print "shutdown" and exit
      reader.close
      process.wait.success?.should be_true
      drained.should contain("shutdown")

      # No corefile from parent or audit-helper child.
      cores = Dir.glob(File.join(workdir, "#{File.basename(bin)}*.core"))
      cores.each { |f| File.delete(f) rescue nil }
      cores.should be_empty
    ensure
      upstream.close rescue nil
      File.delete(bin) rescue nil
      File.delete(log) rescue nil
      File.delete(visits_file) rescue nil
    end
  end
end
