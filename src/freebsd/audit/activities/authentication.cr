# Audit activity values for OCSF class 3002 — Authentication.
#
# Use with `FreeBSD::Audit::Event.write_activity` or
# `FreeBSD::Casper::AuditHelper::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::Authentication::Activity::Logon) do |r|
#   r.subject
#   r.text user: "admin"
#   r.return_success
# end
# ```
module FreeBSD::Audit::Authentication
  # OCSF 3002 activity_id values for Authentication events.
  enum Activity : UInt8
    Unknown              =  0
    Logon                =  1
    Logoff               =  2
    AuthenticationTicket =  3
    ServiceTicketRequest =  4
    ServiceTicketRenew   =  5
    Preauth              =  6
    AccountSwitch        =  7
    Other                = 99

    def aue : AUE
      AUE::Authentication
    end
  end
end
