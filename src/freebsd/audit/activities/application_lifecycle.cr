module FreeBSD::Audit::ApplicationLifecycle
  # OCSF 6002 activity_id values for Application Lifecycle events.
  enum Activity : UInt8
    Unknown =  0
    Install =  1
    Remove  =  2
    Start   =  3
    Stop    =  4
    Other   = 99

    def aue : AUE
      AUE::ApplicationLifecycle
    end
  end
end
