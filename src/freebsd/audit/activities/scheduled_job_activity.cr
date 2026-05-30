# Audit activity values for OCSF class 1006 — Scheduled Job Activity.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::ScheduledJobActivity::Activity::Run) do |r|
#   r.subject
#   r.text job: "backup-db", schedule: "0 3 * * *"
#   r.return_success
# end
# ```
module FreeBSD::Audit::ScheduledJobActivity
  # OCSF 1006 activity_id values for Scheduled Job Activity events.
  enum Activity : UInt8
    Unknown =  0
    Create  =  1
    Update  =  2
    Delete  =  3
    Enable  =  4
    Disable =  5
    Run     =  6
    Other   = 99

    def aue : AUE
      AUE::ScheduledJobActivity
    end
  end
end
