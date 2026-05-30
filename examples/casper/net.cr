# HTTP GET from a Capsicum sandbox — privileged setup via register_net.
#
# register_net injects a Crystal.main_user_code override that opens the Casper
# channel and configures the system.net policy before the Crystal runtime starts
# (before fibers and the event loop). The program body only needs to sandbox!.

require "http/client"

require "../src/freebsd/casper"
require "../src/freebsd/casper/net"

FreeBSD::Casper.register_net(
  FreeBSD::Casper::Service::Net::Mode::Name2Addr |
  FreeBSD::Casper::Service::Net::Mode::ConnectDNS
) do |b|
  b.allow_name2addr("example.com", "80")
end

Time::Location.local
FreeBSD::Capsicum.sandbox!

response = HTTP::Client.get("http://example.com/")
puts "#{response.status_code} #{response.status.description}"
puts response.body[0, 200]

# Confirm the policy is enforced: a different host must be rejected.
begin
  HTTP::Client.get("http://crystal-lang.org/")
  puts "ERROR: request to unlisted host should have been rejected"
rescue ex : Socket::Addrinfo::Error | Socket::ConnectError
  puts "blocked as expected: #{ex.message}"
end
