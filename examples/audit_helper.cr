# Writing BSM audit records from inside a Capsicum sandbox via the
# Casper audit helper.
#
# au_open(3) / au_write(3) require kernel audit facilities that are not
# available inside a Capsicum sandbox — au_open returns -1 after cap_enter.
#
# register_audit_helper forks a privileged helper process via pdfork before
# the Crystal runtime starts. The helper holds the audit pipe and serves
# NVList-encoded write requests from the sandboxed parent. The parent calls
# AuditHelper::Event.write / write_activity with the same token-builder API
# as FreeBSD::Audit::Event.

require "../src/freebsd/casper/audit_helper"

FreeBSD::Casper.register_audit_helper

# Prime any ambient state that requires filesystem access before sandboxing.
Process.pid

FreeBSD::Capsicum.sandbox!

uid = LibC.getuid.to_u32

# ---- Direct event write ----
FreeBSD::Casper::AuditHelper::Event.write(FreeBSD::Audit::AUE::Authentication) do |r|
  r.subject uid: uid
  r.text "user=admin method=password result=success"
  r.address "203.0.113.42"
  r.return_success
end

# ---- Activity-typed write (activity_id token added automatically) ----
FreeBSD::Casper::AuditHelper::Event.write_activity(
  FreeBSD::Audit::Authentication::Activity::Logon
) do |r|
  r.subject uid: uid, terminal: "203.0.113.42"
  r.text "user=admin"
  r.return_success
end

# ---- Discard (useful for testing token construction without a live auditd) ----
FreeBSD::Casper::AuditHelper::Event.discard(FreeBSD::Audit::AUE::Authentication) do |r|
  r.text "dry-run record — not written to audit trail"
  r.return_success
end

puts "Audit records written. To inspect:"
puts "  praudit -l /dev/auditpipe"
puts "  praudit -l /var/audit/current"
