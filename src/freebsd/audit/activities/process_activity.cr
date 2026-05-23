# Audit activity values for OCSF class 1007 — Process Activity.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```crystal
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::ProcessActivity::Activity::Launch) do |r|
#   r.subject
#   r.text cmd: "/usr/bin/ssh", args: "-l root 10.0.0.1"
#   r.return_success
# end
# ```
module FreeBSD::Audit::ProcessActivity
  # OCSF 1007 activity_id values for Process Activity events.
  enum Activity : UInt8
    Unknown   =  0
    Launch    =  1
    Terminate =  2
    Open      =  3
    Inject    =  4
    SetUserId =  5
    Other     = 99

    def aue : AUE
      AUE::ProcessActivity
    end
  end
end
