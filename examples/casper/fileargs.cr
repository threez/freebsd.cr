# File reads from a Capsicum sandbox via register_fileargs.
#
# register_fileargs injects a Crystal.main_user_code override that declares
# the allowed paths and installs the system.fileargs service before the
# Crystal runtime starts. The integrate/file patch is included automatically,
# so plain File.read on declared paths works transparently in the sandbox.

require "../src/freebsd/casper"
require "../src/freebsd/casper/fileargs"

FreeBSD::Casper.register_fileargs(
  ["/etc/hosts", "/etc/resolv.conf"],
  flags: LibC::O_RDONLY,
  fa_flags: FreeBSD::Casper::Service::FileArgs::OPEN |
            FreeBSD::Casper::Service::FileArgs::LSTAT,
)

FreeBSD::Capsicum.sandbox!

# Declared paths work transparently via the integrate/file patch.
puts File.read("/etc/hosts").lines.first(3).join
puts "hosts size: #{File.info("/etc/hosts").size} bytes"

# Undeclared path raises a File::Error.
begin
  File.read("/etc/passwd")
  puts "ERROR: /etc/passwd should have been blocked"
rescue File::Error
  puts "/etc/passwd blocked as expected"
end
