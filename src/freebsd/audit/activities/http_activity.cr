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
