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
