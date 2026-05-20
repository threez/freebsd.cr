# Entry point for FreeBSD privilege-drop helpers.
#
# Provides:
# - `setuid(2)` / `setgid(2)` / `setgroups(2)` / `initgroups(3)` wrappers
#   with Crystal error handling
# - `chroot(2)` support
# - Environment variable scrubbing (`FreeBSD::Privdrop::Env`)
# - `FreeBSD::Privdrop.drop` — one-call convenience wrapper that executes
#   all steps in the correct order
#
# Does NOT require `freebsd/capsicum` or `freebsd/casper`. Use it independently
# or alongside either library.
#
# ```
# require "freebsd/privdrop"
# require "freebsd/capsicum"
#
# # Open everything needed after sandboxing first.
# log = File.open("/var/log/app.log", "a")
#
# # Drop privileges (groups → chroot → setgid → setuid → scrub env).
# FreeBSD::Privdrop.drop(
#   uid: 65534_u32, # nobody
#   gid: 65534_u32,
#   chroot: "/var/empty",
# )
#
# # Enter capability mode — root is already gone.
# FreeBSD::Capsicum.sandbox!
# ```
module FreeBSD::Privdrop
  # True when running on a platform that supports privilege dropping via
  # these bindings (FreeBSD or DragonFlyBSD).
  SUPPORTED = {{ flag?(:freebsd) || flag?(:dragonfly) }}
end

require "./privdrop/errors"
require "./privdrop/lib_privdrop"
require "./privdrop/env"
require "./privdrop/drop"
