module FreeBSD::Audit::DnsActivity
  # OCSF 4003 activity_id values for DNS Activity events.
  enum Activity : UInt8
    Unknown         =  0
    Query           =  1
    Response        =  2
    TrafficQuery    =  3
    TrafficResponse =  4
    Other           = 99

    def aue : AUE
      AUE::DnsActivity
    end
  end
end
