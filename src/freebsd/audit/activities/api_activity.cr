# Audit activity values for OCSF class 6003 — API Activity.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::ApiActivity::Activity::Delete) do |r|
#   r.subject
#   r.text resource: "/api/v1/users/42", method: "DELETE"
#   r.return_success
# end
# ```
module FreeBSD::Audit::ApiActivity
  # OCSF 6003 activity_id values for API Activity events.
  enum Activity : UInt8
    Unknown =  0
    Create  =  1
    Read    =  2
    Update  =  3
    Delete  =  4
    Other   = 99

    def aue : AUE
      AUE::ApiActivity
    end
  end
end
