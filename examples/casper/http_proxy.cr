# An end-to-end proof that FreeBSD::Sandbox.define produces a *useful* sandbox:
# a small HTTP proxy that keeps serving real traffic while running fully inside
# a Capsicum sandbox — dropped to `nobody`, in capability mode — using only the
# resources it declared up front.
#
# ## What it does
#
# It listens on 127.0.0.1:8080 and forwards requests to a fixed allowlist of
# upstream hosts using a trivial protocol:
#
#   GET /proxy?url=http://ifconfig.me/all.json
#
# The method, headers, and body of the incoming request are forwarded to the
# upstream, and the upstream's status, headers, and body are streamed back —
# so a plain `curl` against the proxy returns the same result as calling the
# endpoint directly. It also serves `GET /` (help) and `GET /healthz` (`ok`).
#
# ## Why it proves the sandbox
#
# Every privilege the program needs is acquired *before* `cap_enter`, in the one
# `FreeBSD::Sandbox.define` block, and nothing else is reachable afterwards:
#
#   * `connect_dns ALLOWED` — the Casper `system.net` policy permits DNS+connect
#     to exactly the allowlisted hosts. A request for any other host is rejected
#     at the syscall layer (and we return a clean 403 before even trying).
#   * `bind "listener", ...` — the privileged listener socket is opened as root;
#     its fd survives into the sandbox with just enough rights to `accept`.
#   * `open("access_log", ...)` — the access log fd is opened (append) up front
#     with write-only rights; the sandboxed body can append to it but cannot
#     open any other file.
#   * `audit_helper` — a privileged BSM audit helper is pdfork'd before the
#     runtime starts; the sandboxed body writes audit records through it even
#     though `au_open(3)` is unavailable under capability mode.
#   * `user "nobody", chroot: "/var/empty"` — privileges are dropped and the
#     process is chrooted into an empty directory before `cap_enter`. This is
#     safe only because every filesystem resource was opened above, before the
#     drop; the sandboxed body opens nothing by path.
#
# Direct file access, connecting to an unlisted host, or binding a new port are
# all impossible from the program body. SIGTERM shuts it down cleanly.
#
# ## Run it (root needed for the privileged bind + privdrop)
#
#   crystal build examples/casper/http_proxy.cr -o /tmp/http_proxy
#   sudo /tmp/http_proxy &
#   curl 'http://127.0.0.1:8080/healthz'                                # ok
#   curl 'http://127.0.0.1:8080/proxy?url=http://ifconfig.me/all.json'  # real body
#   curl 'http://127.0.0.1:8080/proxy?url=http://crystal-lang.org/'     # 403 (blocked)
#   tail -f /tmp/http_proxy.access.log                                  # request log
#   sudo praudit -l /dev/auditpipe                                      # audit records
#   kill -TERM %1                                                       # clean exit

require "http/client"
require "http/server"
require "uri"

require "../../src/freebsd/sandbox"
require "../../src/freebsd/casper/net"
require "../../src/freebsd/casper/integrate/dns"
require "../../src/freebsd/casper/integrate/net"
require "../../src/freebsd/casper/audit_helper"
require "../../src/freebsd/casper/helper"

# The ONLY upstreams this proxy may reach, as host => port. Declared before the
# sandbox is entered; the Casper net policy below is derived from it, so nothing
# outside this map is reachable once sandboxed.
ALLOWED = {
  "ifconfig.me" => 80,
  "example.com" => 80,
}

# Where the access log is appended. Opened as root before the privilege drop.
ACCESS_LOG = "/tmp/http_proxy.access.log"

# Per-URL visit counts, persisted by the privileged "visits" helper below.
# The file is owned and written by the *root* helper process; the sandboxed
# (nobody, chrooted, capability-mode) main process cannot open it directly —
# it can only ask the helper to record a visit or report the tallies. This is
# the privsep proof: the privileged work lives in a tiny isolated child.
VISITS_FILE = "/tmp/http_proxy.visits.txt"

# Serve loop for the visits helper. Keeps the tallies in memory, persists them
# to VISITS_FILE on every change, and answers two operations:
#   "visit" — payload is a URL; increment its count, persist, reply "ok".
#   "stats" — reply with the current "<count>\t<url>" table (most-visited first).
# Runs in the pdfork'd child as root, so File IO here is unaffected by the
# parent's privdrop / chroot / cap_enter.
def serve_visits(server)
  counts = Hash(String, Int32).new(0)
  # Resume from any prior run's file so counts survive a restart.
  if File.exists?(VISITS_FILE)
    File.each_line(VISITS_FILE) do |line|
      n, _, url = line.partition('\t')
      counts[url] = n.to_i if url.presence && n.to_i?
    end
  end

  persist = -> do
    File.open(VISITS_FILE, "w") do |f|
      counts.to_a.sort_by! { |(_, c)| -c }.each { |(url, c)| f.puts "#{c}\t#{url}" }
    end
  end

  server.serve do |op, payload|
    case op
    when "visit"
      counts[String.new(payload)] += 1
      persist.call
      "ok".to_slice
    when "stats"
      counts.to_a.sort_by! { |(_, c)| -c }
        .map { |(url, c)| "#{c}\t#{url}" }.join('\n').to_slice
    else
      raise "unknown op: #{op}"
    end
  end
end

FreeBSD::Sandbox.define do
  # Privileged BSM audit helper, forked via pdfork(2) before the runtime starts.
  audit_helper

  # Privileged "visits" helper, also pdfork'd before the runtime (so it stays
  # root after the parent drops privileges). It owns VISITS_FILE; the sandboxed
  # parent talks to it over the helper channel via FreeBSD::Casper::Helper.client.
  helper("visits") { |server| serve_visits(server) }

  # system.net policy: resolve + connect to each allowlisted host:port, nothing
  # else. `connect_dns` accepts the host => port Hash directly.
  connect_dns ALLOWED

  # Prime /etc/localtime before cap_enter so Time.local works for log stamps.
  tz_data

  # Access log fd, opened append as root and carried into the sandbox with
  # write-only rights — enough to append, not to read or reposition arbitrarily.
  open("access_log", File, rights: [:write, :seek, :fstat, :fsync, :fcntl]) do
    File.open(ACCESS_LOG, "a")
  end

  # Privileged listener bound as root; the fd survives cap_enter. In Capsicum
  # an accepted socket *inherits* its listener's rights, so this set must cover
  # both the accept on the listener and the read/write/peer/event operations the
  # HTTP server performs on each accepted connection.
  bind "listener", "127.0.0.1", 8080,
    rights: [:accept, :listen, :read, :write, :event, :fcntl,
             :getsockname, :getpeername, :getsockopt, :setsockopt, :shutdown]

  # Drop privileges once everything above is open, then enter capability mode.
  # `chroot: "/var/empty"` confines the process to an empty directory: safe here
  # because every filesystem resource (the log fd, the timezone cache) was
  # already acquired above, before the drop — the sandboxed body opens nothing
  # by path, so the new root needs to contain nothing.
  user "nobody", chroot: "/var/empty"
end

# ---- everything below runs sandboxed (capability mode, dropped to nobody) ----

log      = FreeBSD::Sandbox.access_log              # => File   (write-only append)
listener = FreeBSD::Sandbox.listener                # => TCPServer (privileged, carried fd)
uid      = FreeBSD::Sandbox.uid.to_u32              # the dropped-to uid (nobody)
visits   = FreeBSD::Casper::Helper.client("visits") # channel to the root helper

# Hop-by-hop headers must not be forwarded verbatim; HTTP::Client manages them.
HOP_BY_HOP = %w[host connection content-length transfer-encoding keep-alive
  proxy-connection te trailer upgrade]

# Append one line per request to the carried log fd.
log_request = ->(remote : String, method : String, target : String, status : Int32) do
  log.puts "#{Time.local.to_rfc3339} #{remote} #{method} #{target} -> #{status}"
  log.flush
end

# Write a BSM audit record for a proxied request through the pdfork'd helper.
audit_request = ->(remote : String, target : String, ok : Bool) do
  FreeBSD::Casper::AuditHelper::Event.write_activity(
    FreeBSD::Audit::ApiActivity::Activity::Create
  ) do |r|
    r.subject uid: uid
    r.text resource: target, client: remote
    ok ? r.return_success : r.return_failure(Errno::EACCES)
  end
end

server = HTTP::Server.new do |context|
  request  = context.request
  response = context.response
  remote   = request.remote_address.try(&.to_s) || "-"

  case request.path
  when "/"
    response.content_type = "text/plain"
    response.print <<-HELP
      sandboxed http proxy

      GET /proxy?url=<http-url>   forward to an allowlisted upstream
      GET /stats                  per-url visit counts (from the root helper)
      GET /healthz                liveness check

      allowed upstreams:
      #{ALLOWED.map { |h, p| "  #{h}:#{p}" }.join('\n')}
      HELP
    log_request.call(remote, request.method, request.path, response.status_code)
  when "/healthz"
    response.content_type = "text/plain"
    response.print "ok"
    log_request.call(remote, request.method, request.path, 200)
  when "/stats"
    # The sandboxed process can't read VISITS_FILE (root-owned, and it's chrooted
    # into an empty dir anyway) — it asks the privileged helper for the tallies.
    response.content_type = "text/plain"
    response.print String.new(visits.request("stats"))
    log_request.call(remote, request.method, request.path, 200)
  when "/proxy"
    target = request.query_params["url"]?

    if target.nil? || target.empty?
      response.respond_with_status(:bad_request, "missing url parameter")
      log_request.call(remote, request.method, "-", response.status_code)
      next
    end

    uri  = URI.parse(target)
    host = uri.host
    port = uri.port || 80

    # Defence in depth: refuse anything not in the allowlist with a clean 403
    # rather than letting the Casper net policy turn it into a connect error.
    unless uri.scheme == "http" && host && ALLOWED[host]? == port
      response.respond_with_status(:forbidden, "host not allowed: #{host}:#{port}")
      log_request.call(remote, request.method, target, response.status_code)
      audit_request.call(remote, target, false)
      next
    end

    # Forward the request to the upstream through the Casper-routed client.
    fwd_headers = HTTP::Headers.new
    request.headers.each do |name, values|
      next if HOP_BY_HOP.includes?(name.downcase)
      values.each { |v| fwd_headers.add(name, v) }
    end

    path = uri.request_target
    body = request.body

    begin
      HTTP::Client.new(host, port) do |client|
        client.exec(request.method, path, headers: fwd_headers, body: body) do |upstream|
          response.status = upstream.status
          upstream.headers.each do |name, values|
            next if HOP_BY_HOP.includes?(name.downcase)
            values.each { |v| response.headers.add(name, v) }
          end
          IO.copy(upstream.body_io, response)
        end
      end
      log_request.call(remote, request.method, target, response.status_code)
      audit_request.call(remote, target, true)
      # Record the visit in the privileged helper (it owns the root-only file).
      visits.request("visit", target.to_slice)
    rescue ex
      response.respond_with_status(:bad_gateway, "upstream error: #{ex.message}")
      log_request.call(remote, request.method, target, response.status_code)
      audit_request.call(remote, target, false)
    end
  else
    response.respond_with_status(:not_found, "not found")
    log_request.call(remote, request.method, request.path, response.status_code)
  end
end

# Reuse the privileged listener opened before the sandbox — `bind(socket)`
# adopts it without re-binding (a fresh bind would fail under capability mode).
server.bind(listener)

addr = listener.local_address
puts "sandboxed http proxy listening on #{addr} (pid #{Process.pid})"
puts "send SIGTERM to stop"
STDOUT.flush

# SIGTERM closes the server, which closes the listener and makes #listen return.
Signal::TERM.trap { server.close }

server.listen # blocks until the server is closed

log.flush
log.close
puts "shut down cleanly"
