# Writing BSM audit records from inside a Capsicum sandbox via the
# Casper audit helper.
#
# au_open(3) / au_write(3) require kernel audit facilities that are not
# available inside a Capsicum sandbox — au_open(3) returns -1 after
# cap_enter(2). The Casper audit helper solves this by forking a privileged
# helper process via pdfork(2) *before* sandboxing. The helper holds the
# audit pipe and serves NVList-encoded requests; the sandboxed parent calls
# AuditHelper::Event.write / write_activity with the same token-builder API
# as FreeBSD::Audit::Event.
#
# To inspect records written by this program:
#   praudit -l /dev/auditpipe       # live stream
#   praudit -l /var/audit/current   # current trail file

require "../src/freebsd/casper/audit_helper"

# Fork the audit helper before the sandbox. Must be called at top level,
# not inside a block or fiber.
FreeBSD::Casper.register_audit_helper

# Resolve any filesystem state needed later (e.g. timezone, locale) while
# we still have unrestricted access.
uid = LibC.getuid.to_u32
pid = Process.pid

FreeBSD::Capsicum.sandbox!

# ---- 1. Direct event write via AUE constant --------------------------------
#
# Use when you need full control over which AUE number is recorded and do
# not want an activity_id token.
FreeBSD::Casper::AuditHelper::Event.write(FreeBSD::Audit::AUE::Authentication) do |r|
  r.subject uid: uid
  r.text user: "admin", method: "password"
  r.address "203.0.113.42"
  r.return_success
end

# ---- 2. Activity-typed write (preferred) ------------------------------------
#
# write_activity prepends the activity_id token automatically and derives
# the AUE from the Activity enum's #aue method.
FreeBSD::Casper::AuditHelper::Event.write_activity(
  FreeBSD::Audit::Authentication::Activity::Logon
) do |r|
  r.subject uid: uid, terminal: "203.0.113.42"
  r.text user: "admin", result: "success"
  r.return_success
end

# ---- 3. Errno overload for failures ----------------------------------------
FreeBSD::Casper::AuditHelper::Event.write_activity(
  FreeBSD::Audit::Authentication::Activity::Logon
) do |r|
  r.subject uid: uid
  r.text user: "badactor", result: "failure"
  r.return_failure Errno::EACCES
end

# ---- 4. Socket::IPAddress overload -----------------------------------------
#
# When the peer address comes from an accepted socket you can pass it
# directly — the port is stripped automatically.
peer = Socket::IPAddress.new("198.51.100.7", 54321)

FreeBSD::Casper::AuditHelper::Event.write_activity(
  FreeBSD::Audit::NetworkActivity::Activity::Refuse
) do |r|
  r.subject uid: uid
  r.address peer
  r.return_failure Errno::EACCES
end

# ---- 5. Multiple activity types --------------------------------------------
[
  FreeBSD::Audit::ApiActivity::Activity::Create,
  FreeBSD::Audit::FileSystemActivity::Activity::Open,
].each do |activity|
  FreeBSD::Casper::AuditHelper::Event.write_activity(activity) do |r|
    r.subject uid: uid
    r.text resource: "/api/v1/data", pid: pid.to_s
    r.return_success
  end
end

# ---- 6. Discard (dry-run without writing to the audit trail) ---------------
#
# Useful in tests or when you want to exercise token construction without
# a live auditd.
FreeBSD::Casper::AuditHelper::Event.discard(FreeBSD::Audit::AUE::Authentication) do |r|
  r.text "dry-run — this record is not written to the audit trail"
  r.return_success
end

puts "Done. Records written to the audit trail (except the discard example)."
