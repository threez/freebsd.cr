# An end-to-end proof that the `directory` directive produces a *useful* sandbox:
# a small static-file HTTP server that keeps serving real files while running
# fully inside a Capsicum sandbox — dropped to `nobody`, in capability mode —
# opening every file it serves via `openat(2)` beneath a directory fd it opened
# up front.
#
# ## What it does
#
# It listens on 127.0.0.1:8080 and serves files out of a document root:
#
#   GET /                serves the pre-opened index.html (from a carried fd)
#   GET /<path>          serves <docroot>/<path> via openat under the docroot fd
#   GET /list            a directory index, listed via fdopendir under the dir fd
#   GET /healthz         "ok"
#
# Two distinct file-access mechanisms are on display:
#
#   * The **document root** is pre-opened as a `directory` fd before cap_enter.
#     Requiring `freebsd/capsicum/integrate/file` routes `File.open` of any path
#     beneath it through `openat` — so the ordinary `File.open(...)` in the
#     handler Just Works inside the sandbox, where `open(2)` is forbidden.
#   * The **index page** is additionally pre-opened by path as one specific file
#     (`open("index", File, ...)`), demonstrating the "carry one exact fd" case
#     alongside the directory case. `GET /` streams it directly.
#
# ## Why it proves the sandbox
#
# Every privilege is acquired *before* `cap_enter`, in the one
# `FreeBSD::Sandbox.define` block, and nothing else is reachable afterwards:
#
#   * `directory "wwwroot", DOCROOT, rights: [:lookup, :read, :fstat]` — a dir fd
#     opened as root, rights-limited (read-only traversal) before cap_enter, and
#     registered so `File.open` beneath it routes through `openat`. A request for
#     a path that escapes the docroot (`..`, absolute) is rejected by the handler
#     and, defence-in-depth, by `O_RESOLVE_BENEATH` in the kernel.
#   * `open("index", File, rights: [:read, :fstat])` — the index fd, carried in.
#   * `bind "listener", ...` — the privileged listener socket, opened as root.
#
# ## Chroot caveat
#
# Unlike `http_proxy.cr`, this body opens files *by path* after `cap_enter`, so
# the registered base path must stay resolvable. We therefore do **not** chroot:
# a `chroot:` would change what `DOCROOT` resolves to. If you do want a chroot,
# register the directory at its post-chroot path and serve relative to that.
#
# ## Run it (root needed for the privileged bind + privdrop)
#
#   mkdir -p /tmp/static_site
#   echo '<h1>hello from the sandbox</h1>' > /tmp/static_site/index.html
#   echo 'body { font-family: sans-serif }' > /tmp/static_site/style.css
#   crystal build examples/casper/static_server.cr -o /tmp/static_server
#   sudo /tmp/static_server &
#   curl 127.0.0.1:8080/               # index.html, served from the carried fd
#   curl 127.0.0.1:8080/style.css      # served via openat under the docroot
#   curl 127.0.0.1:8080/../etc/passwd  # 403 (rejected before any open)
#   curl 127.0.0.1:8080/healthz        # ok
#   kill -TERM %1                       # clean exit

require "http/server"

require "../../src/freebsd/sandbox"
# Routes File.open of paths beneath a registered `directory` through openat,
# and File.info?/exists? through fstatat/faccessat.
require "../../src/freebsd/capsicum/integrate/file"
# Routes Dir.children/entries beneath a registered `directory` through fdopendir,
# so the /list directory index works under cap_enter.
require "../../src/freebsd/capsicum/integrate/dir"

# The document root served by this process. Opened as a directory fd before the
# sandbox is entered; nothing outside it is reachable once sandboxed.
DOCROOT = "/tmp/static_site"

FreeBSD::Sandbox.define do
  # Pre-open the document root as a directory fd, rights-limited to read-only
  # traversal, and register it so File.open beneath it routes through openat.
  directory "wwwroot", DOCROOT, rights: [:lookup, :read, :fstat]

  # Also carry one specific file by fd: the index page, served on GET /.
  # `:seek` is needed because the handler rewinds the fd before each send.
  open("index", File, rights: [:read, :seek, :fstat]) { File.open(File.join(DOCROOT, "index.html"), "r") }

  # Privileged listener bound as root; its fd survives cap_enter. The rights must
  # cover both the accept on the listener and the read/write/event operations the
  # HTTP server performs on each accepted connection.
  bind "listener", "127.0.0.1", 8080,
    rights: [:accept, :listen, :read, :write, :event, :fcntl,
             :getsockname, :getpeername, :getsockopt, :setsockopt, :shutdown]

  # Drop to an unprivileged user once everything above is open. No chroot — the
  # handler opens files by path under DOCROOT after cap_enter (see the caveat in
  # the header comment).
  user "nobody"
end

# ---- everything below runs sandboxed (capability mode, dropped to nobody) ----

index = FreeBSD::Sandbox.index       # => File  (the carried index fd)
listener = FreeBSD::Sandbox.listener # => TCPServer (privileged, carried fd)

CONTENT_TYPES = {
  ".html" => "text/html",
  ".css"  => "text/css",
  ".js"   => "application/javascript",
  ".json" => "application/json",
  ".txt"  => "text/plain",
}

# Reject anything that isn't a simple relative path beneath the docroot. The
# kernel re-checks via O_RESOLVE_BENEATH, but failing fast gives a clean 403.
def safe_relative?(path : String) : Bool
  return false if path.empty?
  return false if path.starts_with?('/')
  Path[path].parts.none? { |part| part == ".." }
end

server = HTTP::Server.new do |context|
  request = context.request
  response = context.response

  case request.path
  when "/healthz"
    response.content_type = "text/plain"
    response.print "ok"
  when "/", "/index.html"
    # Serve the pre-opened index fd directly (rewound each request).
    response.content_type = "text/html"
    index.rewind
    IO.copy(index, response)
  when "/list"
    # Directory index: list the docroot via fdopendir under the registered dir
    # fd (Dir.children is routed by integrate/dir). Proves listing works sandboxed.
    response.content_type = "text/html"
    response.print "<h1>index of /</h1>\n<ul>\n"
    Dir.children(DOCROOT).sort.each do |name|
      response.print %(<li><a href="/#{name}">#{name}</a></li>\n)
    end
    response.print "</ul>\n"
  else
    rel = request.path.lchop('/')

    unless safe_relative?(rel)
      response.respond_with_status(:forbidden, "forbidden path")
      next
    end

    full = File.join(DOCROOT, rel)
    begin
      # File.open is transparently routed through the docroot's openat.
      File.open(full, "r") do |file|
        ext = Path[rel].extension
        response.content_type = CONTENT_TYPES[ext]? || "application/octet-stream"
        IO.copy(file, response)
      end
    rescue File::Error
      response.respond_with_status(:not_found, "not found")
    end
  end
end

# Reuse the privileged listener opened before the sandbox — `bind(socket)`
# adopts it without re-binding (a fresh bind would fail under capability mode).
server.bind(listener)

addr = listener.local_address
puts "sandboxed static server listening on #{addr} (pid #{Process.pid}), docroot #{DOCROOT}"
puts "send SIGTERM to stop"
STDOUT.flush

Signal::TERM.trap { server.close }

server.listen # blocks until the server is closed

puts "shut down cleanly"
