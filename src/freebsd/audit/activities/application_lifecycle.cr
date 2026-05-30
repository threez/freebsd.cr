# Audit activity values for OCSF class 6002 — Application Lifecycle.
#
# Use with `FreeBSD::Audit::Event.write_activity`:
#
# ```
# FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::ApplicationLifecycle::Activity::Start) do |r|
#   r.subject
#   r.text app: "nginx", version: "1.25.3"
#   r.return_success
# end
# ```
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
