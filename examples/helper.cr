# Custom privsep helper registered via FreeBSD::Casper::Helper.register.
#
# Helper.register installs a Crystal.main_user_code override that:
#   1. Creates a socket pair (before the runtime — no event-loop touch)
#   2. Forks the helper child via pdfork(2)
#   3. Starts the Crystal runtime independently in both processes
#
# Both helper and client get a full runtime, so the helper block can use
# File.read, Crystal IO, etc. normally. The child exits after serving.
# The client is available via Helper.client after the register call.

require "../src/freebsd/capsicum"
require "../src/freebsd/casper/helper"

FreeBSD::Casper::Helper.register(name: "files") do |server|
  server.serve do |op, payload|
    case op
    when "read" then File.read(String.new(payload)).to_slice
    when "ping" then "pong".to_slice
    else             raise "unknown op: #{op}"
    end
  end
end

client = FreeBSD::Casper::Helper.client(name: "files")

FreeBSD::Capsicum.sandbox!

puts String.new(client.request("ping"))
puts String.new(client.request("read", "/etc/hosts".to_slice))[0, 40].strip

begin
  File.read("/etc/hosts")
  puts "ERROR: direct read should have been blocked"
rescue File::Error
  puts "direct file read blocked as expected"
end
