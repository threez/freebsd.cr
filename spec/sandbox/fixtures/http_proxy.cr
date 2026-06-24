# Fixture for the sandboxed-HTTP-proxy regression (http_proxy_spec.cr).
#
# A root-free trim of examples/casper/http_proxy.cr: no `user` drop (the spec
# runs unprivileged), an ephemeral listener (port 0), a temp access log, and the
# upstream allowlist built from env vars set by the driver:
#
#   PROXY_LOG       — path of the access log to open (append)
#   UPSTREAM_HOST   — host of the in-spec echo upstream (e.g. "localhost")
#   UPSTREAM_PORT   — its port
#
# It still exercises the full sandbox shape — a pdfork'd audit_helper, a
# connect_dns net policy, a carried writable log fd, and a carried privileged
# listener — so a helper child must traverse NONE of the post-runtime setup
# (the single `unless Helper.is_helper` guard in `define`), and the carried fds
# must keep working under capability mode.
#
# Protocol: it announces `listen <host> <port>` on stdout; the driver connects,
# drives /healthz and /proxy, then sends SIGTERM. The body prints `shutdown` and
# exits 0 once #listen returns.

require "http/client"
require "http/server"
require "uri"

require "../../../src/freebsd/sandbox"
require "../../../src/freebsd/casper/net"
require "../../../src/freebsd/casper/integrate/dns"
require "../../../src/freebsd/casper/integrate/net"
require "../../../src/freebsd/casper/audit_helper"
require "../../../src/freebsd/casper/helper"

UPSTREAM_HOST = ENV["UPSTREAM_HOST"]
UPSTREAM_PORT = ENV["UPSTREAM_PORT"].to_i
ACCESS_LOG    = ENV["PROXY_LOG"]
VISITS_FILE   = ENV["VISITS_FILE"]

# The only reachable upstream: the driver's echo server.
ALLOWED = {UPSTREAM_HOST => UPSTREAM_PORT}

# Serve loop for the visits helper — runs in the second pdfork'd root child,
# alongside the audit helper. Owns VISITS_FILE; answers "visit"/"stats". This
# is the multi-helper composition the driver asserts works.
def serve_visits(server)
  counts = Hash(String, Int32).new(0)
  server.serve do |op, payload|
    case op
    when "visit"
      counts[String.new(payload)] += 1
      File.open(VISITS_FILE, "w") do |f|
        counts.each { |url, c| f.puts "#{c}\t#{url}" }
      end
      "ok".to_slice
    when "stats"
      counts.map { |url, c| "#{c}\t#{url}" }.join('\n').to_slice
    else
      raise "unknown op: #{op}"
    end
  end
end

FreeBSD::Sandbox.define do
  audit_helper
  helper("visits") { |server| serve_visits(server) }
  connect_dns ALLOWED
  tz_data # prime /etc/localtime so Time.local works for log timestamps
  open("access_log", File, rights: [:write, :seek, :fstat, :fsync, :fcntl]) do
    File.open(ACCESS_LOG, "a")
  end
  # Accepted sockets inherit the listener's rights under Capsicum, so include
  # everything the HTTP server does on a connection (read/write/peer/event).
  bind "listener", "127.0.0.1", 0,
    rights: [:accept, :listen, :read, :write, :event, :fcntl,
             :getsockname, :getpeername, :getsockopt, :setsockopt, :shutdown]
end

# ---- sandboxed body ----

log      = FreeBSD::Sandbox.access_log
listener = FreeBSD::Sandbox.listener
uid      = FreeBSD::Sandbox.uid.to_u32
visits   = FreeBSD::Casper::Helper.client("visits")

HOP_BY_HOP = %w[host connection content-length transfer-encoding keep-alive
  proxy-connection te trailer upgrade]

server = HTTP::Server.new do |context|
  request  = context.request
  response = context.response
  remote   = request.remote_address.try(&.to_s) || "-"

  case request.path
  when "/healthz"
    response.content_type = "text/plain"
    response.print "ok"
    log.puts "#{Time.local.to_rfc3339} #{remote} healthz"
    log.flush
  when "/stats"
    response.content_type = "text/plain"
    response.print String.new(visits.request("stats"))
  when "/proxy"
    target = request.query_params["url"]?
    uri    = target ? URI.parse(target) : nil
    host   = uri.try(&.host)
    port   = uri.try(&.port) || 80

    if uri.nil? || uri.scheme != "http" || host.nil? || ALLOWED[host]? != port
      response.respond_with_status(:forbidden, "host not allowed")
      log.puts "#{Time.local.to_rfc3339} #{remote} forbidden #{target}"
      log.flush
      FreeBSD::Casper::AuditHelper::Event.write_activity(
        FreeBSD::Audit::ApiActivity::Activity::Create
      ) do |r|
        r.subject uid: uid
        r.text resource: target.to_s
        r.return_failure Errno::EACCES
      end
      next
    end

    fwd = HTTP::Headers.new
    request.headers.each do |name, values|
      next if HOP_BY_HOP.includes?(name.downcase)
      values.each { |v| fwd.add(name, v) }
    end

    HTTP::Client.new(host, port) do |client|
      client.exec(request.method, uri.not_nil!.request_target, headers: fwd, body: request.body) do |upstream|
        response.status = upstream.status
        upstream.headers.each do |name, values|
          next if HOP_BY_HOP.includes?(name.downcase)
          values.each { |v| response.headers.add(name, v) }
        end
        IO.copy(upstream.body_io, response)
      end
    end
    log.puts "#{Time.local.to_rfc3339} #{remote} proxy #{target} -> #{response.status_code}"
    log.flush
    visits.request("visit", target.to_s.to_slice)
    FreeBSD::Casper::AuditHelper::Event.write_activity(
      FreeBSD::Audit::ApiActivity::Activity::Create
    ) do |r|
      r.subject uid: uid
      r.text resource: target.to_s
      r.return_success
    end
  else
    response.respond_with_status(:not_found, "not found")
  end
end

server.bind(listener)

addr = listener.local_address
STDOUT.puts "listen #{addr.address} #{addr.port}"
STDOUT.flush

Signal::TERM.trap { server.close }

server.listen

log.flush
log.close
STDOUT.puts "shutdown"
STDOUT.flush
