# Password-database lookups from a Capsicum sandbox via register_pwd.
#
# register_pwd injects a Crystal.main_user_code override that opens the Casper
# channel and configures system.pwd before the Crystal runtime starts.
# The program body calls sandbox! and uses the service directly.

require "../src/freebsd/casper"
require "../src/freebsd/casper/pwd"

FreeBSD::Casper.register_pwd do |pwd|
  pwd.limit_users(names: ["root", "nobody"])
  pwd.limit_cmds("getpwnam", "getpwuid")
end

FreeBSD::Capsicum.sandbox!

pwd = FreeBSD::Casper.pwd?.not_nil!

if u = pwd.getpwnam("root")
  puts "root: uid=#{u.uid} shell=#{u.shell}"
else
  puts "ERROR: root not found"
end

if u = pwd.getpwuid(65534_u32)
  puts "nobody: name=#{u.name} uid=#{u.uid}"
else
  puts "nobody not found (uid 65534 may not exist on this system)"
end

# Confirm policy is enforced — daemon is not in the allow-list so the
# service returns nil rather than a record.
if pwd.getpwnam("daemon").nil?
  puts "daemon lookup blocked as expected"
else
  puts "ERROR: daemon should have been blocked"
end
