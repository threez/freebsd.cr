# Entry point for FreeBSD BSM audit helpers.
#
# Wraps `libbsm` (`au_open`/`au_write`/`au_close`) and the `au_to_*` token
# constructors behind a Crystal-idiomatic builder API, allowing Crystal
# applications to write structured custom audit events to the FreeBSD audit
# subsystem.
#
# Does NOT require `freebsd/capsicum` or `freebsd/casper`. Use it independently
# or alongside either library.
#
# ```
# require "freebsd/audit"
#
# FreeBSD::Audit::Event.write(FreeBSD::Audit::AUE::WebAuthFail) do |r|
#   r.subject uid: 80_u32
#   r.text "username=admin method=POST path=/login"
#   r.address "203.0.113.42"
#   r.return_failure errno: Errno::EACCES.value.to_u32
# end
# ```
module FreeBSD::Audit
  # True when running on a platform that supports BSM audit via these
  # bindings (FreeBSD or DragonFlyBSD).
  SUPPORTED = {{ flag?(:freebsd) || flag?(:dragonfly) }}
end

require "./audit/errors"
require "./audit/lib_bsm"
require "./audit/aue"
require "./audit/record"
require "./audit/event"
require "./audit/activities/authentication"
require "./audit/activities/file_system_activity"
require "./audit/activities/process_activity"
require "./audit/activities/network_activity"
require "./audit/activities/api_activity"
require "./audit/activities/account_change"
require "./audit/activities/http_activity"
require "./audit/activities/dns_activity"
require "./audit/activities/application_lifecycle"
require "./audit/activities/scheduled_job_activity"
