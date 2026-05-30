# Audit activity values for OCSF class 3001 — Account Change.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::AccountChange::Activity::PasswordReset) do |r|
#   r.subject
#   r.text user: "alice"
#   r.return_success
# end
# ```
module FreeBSD::Audit::AccountChange
  # OCSF 3001 activity_id values for Account Change events.
  enum Activity : UInt8
    Unknown        =  0
    Create         =  1
    Enable         =  2
    Disable        =  3
    Delete         =  4
    Lock           =  5
    Unlock         =  6
    PasswordChange =  7
    PasswordReset  =  8
    MfaAdd         =  9
    MfaRemove      = 10
    Other          = 99

    def aue : AUE
      AUE::AccountChange
    end
  end
end
