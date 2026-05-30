# Audit activity values for OCSF class 4001 — Network Activity.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::NetworkActivity::Activity::Refuse) do |r|
#   r.subject
#   r.address remote_ip
#   r.return_failure Errno::EACCES
# end
# ```
module FreeBSD::Audit::NetworkActivity
  # OCSF 4001 activity_id values for Network Activity events.
  enum Activity : UInt8
    Unknown =  0
    Open    =  1
    Close   =  2
    Reset   =  3
    Fail    =  4
    Refuse  =  5
    Traffic =  6
    Listen  =  7
    Other   = 99

    def aue : AUE
      AUE::NetworkActivity
    end
  end
end
