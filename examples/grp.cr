# Group-database lookups from a Capsicum sandbox via register_grp.
#
# register_grp injects a Crystal.main_user_code override that opens the Casper
# channel and configures system.grp before the Crystal runtime starts.
# The program body calls sandbox! and uses the service directly.

require "../src/freebsd/casper"
require "../src/freebsd/casper/grp"

FreeBSD::Casper.register_grp do |grp|
  grp.limit_groups(names: ["wheel", "nobody"])
  grp.limit_cmds("getgrnam", "getgrgid")
end

FreeBSD::Capsicum.sandbox!

grp = FreeBSD::Casper.grp?.not_nil!

if g = grp.getgrnam("wheel")
  puts "wheel: gid=#{g.gid} members=#{g.members.join(", ")}"
else
  puts "ERROR: wheel not found"
end

if g = grp.getgrgid(65534_u32)
  puts "nobody: name=#{g.name} gid=#{g.gid}"
else
  puts "nobody not found (gid 65534 may not exist on this system)"
end

# Confirm policy is enforced — daemon is not in the allow-list so
# the service returns nil.
if grp.getgrnam("daemon").nil?
  puts "daemon lookup blocked as expected"
else
  puts "ERROR: daemon should have been blocked"
end
