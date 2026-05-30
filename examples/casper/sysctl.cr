# Sysctl reads from a Capsicum sandbox via register_sysctl.
#
# register_sysctl injects a Crystal.main_user_code override that opens the
# Casper channel and configures system.sysctl before the Crystal runtime
# starts. The program body calls sandbox! and uses the service directly.

require "../src/freebsd/casper"
require "../src/freebsd/casper/sysctl"

FreeBSD::Casper.register_sysctl do |sys|
  sys.limit({
    "kern.ostype"    => FreeBSD::Casper::Service::Sysctl::Mode::Read,
    "kern.osrelease" => FreeBSD::Casper::Service::Sysctl::Mode::Read,
    "kern.hostname"  => FreeBSD::Casper::Service::Sysctl::Mode::Read,
  })
end

FreeBSD::Capsicum.sandbox!

sys = FreeBSD::Casper.sysctl?.not_nil!

puts "ostype:    #{sys.get_string("kern.ostype")}"
puts "osrelease: #{sys.get_string("kern.osrelease")}"
puts "hostname:  #{sys.get_string("kern.hostname")}"

# Confirm policy is enforced — kern.version is not in the allow-list.
begin
  sys.get_string("kern.version")
  puts "ERROR: kern.version should have been blocked"
rescue FreeBSD::Capsicum::Error
  puts "kern.version blocked as expected"
end
