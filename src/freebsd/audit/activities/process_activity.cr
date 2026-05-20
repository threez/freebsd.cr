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
