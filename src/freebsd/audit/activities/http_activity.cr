# Audit activity values for OCSF class 4002 — HTTP Activity.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::HttpActivity::Activity::Refuse) do |r|
#   r.subject
#   r.address remote_ip
#   r.text method: "POST", path: "/admin"
#   r.return_failure Errno::EACCES
# end
# ```
module FreeBSD::Audit::HttpActivity
  # OCSF 4002 activity_id values for HTTP Activity events.
  enum Activity : UInt8
    Unknown =  0
    Connect =  1
    Receive =  2
    Refuse  =  3
    Close   =  4
    Other   = 99

    def aue : AUE
      AUE::HttpActivity
    end
  end
end
