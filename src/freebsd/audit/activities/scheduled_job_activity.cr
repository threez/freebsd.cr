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
