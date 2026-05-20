module FreeBSD::Audit
  # BSM audit event numbers mapped directly from OCSF class UIDs.
  #
  # ## Mapping rule
  #
  # ```
  # bsm_event_number = ocsf_class_uid + 40000
  # ```
  #
  # Any developer who knows an OCSF class UID can derive the BSM number
  # immediately, and vice versa. Example: Authentication (OCSF 3002) → 43002.
  #
  # ## Ranges
  #
  # | BSM range     | Source                                                   |
  # |---------------|----------------------------------------------------------|
  # | 1–6143        | FreeBSD/Solaris kernel syscall events                    |
  # | 6144–7003     | Solaris userspace + historic Darwin events               |
  # | 32768–32800   | Third-party allocations (e.g. AUE_openssh = 32800)      |
  # | 41001–41008   | OCSF category 1 — System Activity                       |
  # | 42001–42006   | OCSF category 2 — Findings                               |
  # | 43001–43006   | OCSF category 3 — Identity & Access                     |
  # | 44001–44014   | OCSF category 4 — Network Activity                      |
  # | 45001–45020   | OCSF category 5 — Discovery  ¹                          |
  # | 46001–46007   | OCSF category 6 — Application Activity                  |
  # | 47001–47004   | OCSF category 7 — Remediation                           |
  # | 45000–45030   | OpenBSM-managed Darwin application events  ¹             |
  # | 32768–65535   | General third-party application space (OpenBSM spec)     |
  #
  # ¹ The OCSF category-5 range (45001–45020) overlaps with the OpenBSM-managed
  #   Darwin block (45000–45030). On FreeBSD the Darwin events are never generated
  #   by the kernel, so the overlap is harmless in practice. Both namespaces are
  #   documented here for clarity.
  #
  # See https://schema.ocsf.io for the OCSF specification.
  enum AUE : UInt16
    None = 0

    # -------------------------------------------------------------------------
    # OCSF Category 1 — System Activity (OCSF 1001–1008 → BSM 41001–41008)
    # -------------------------------------------------------------------------

    # OCSF 1001: File System Activity — process action on a file or folder.
    FileSystemActivity = 41001

    # OCSF 1002: Kernel Extension Activity — driver/extension loaded or unloaded.
    KernelExtensionActivity = 41002

    # OCSF 1003: Kernel Activity — process creates, reads, or deletes a kernel resource.
    KernelActivity = 41003

    # OCSF 1004: Memory Activity — memory allocation, read, modification, or manipulation.
    MemoryActivity = 41004

    # OCSF 1005: Module Activity — process loads or unloads a module.
    ModuleActivity = 41005

    # OCSF 1006: Scheduled Job Activity — scheduled job or task actions.
    ScheduledJobActivity = 41006

    # OCSF 1007: Process Activity — process launch, inject, open, or terminate.
    ProcessActivity = 41007

    # OCSF 1008: Event Log Activity — logging service actions (clear, disable).
    EventLogActivity = 41008

    # -------------------------------------------------------------------------
    # OCSF Category 2 — Findings (OCSF 2001–2006 → BSM 42001–42006)
    # -------------------------------------------------------------------------

    # OCSF 2001: Security Finding — detections and anomalies from security products.
    SecurityFinding = 42001

    # OCSF 2002: Vulnerability Finding — weakness that could be exploited.
    VulnerabilityFinding = 42002

    # OCSF 2003: Compliance Finding — evaluation against compliance standards.
    ComplianceFinding = 42003

    # OCSF 2004: Detection Finding — correlation-engine detections/alerts.
    DetectionFinding = 42004

    # OCSF 2005: Incident Finding — security incident creation, update, or closure.
    IncidentFinding = 42005

    # OCSF 2006: Data Security Finding — DLP and DSPM detections.
    DataSecurityFinding = 42006

    # -------------------------------------------------------------------------
    # OCSF Category 3 — Identity & Access (OCSF 3001–3006 → BSM 43001–43006)
    # -------------------------------------------------------------------------

    # OCSF 3001: Account Change — user account management (create, delete, modify).
    AccountChange = 43001

    # OCSF 3002: Authentication — logon, logoff, and session authentication.
    Authentication = 43002

    # OCSF 3003: Authorize Session — privileges or groups assigned to new sessions.
    AuthorizeSession = 43003

    # OCSF 3004: Entity Management — CRUD operations on managed entities.
    EntityManagement = 43004

    # OCSF 3005: User Access Management — updates to user privileges.
    UserAccessManagement = 43005

    # OCSF 3006: Group Management — updates to group membership and permissions.
    GroupManagement = 43006

    # -------------------------------------------------------------------------
    # OCSF Category 4 — Network Activity (OCSF 4001–4014 → BSM 44001–44014)
    # -------------------------------------------------------------------------

    # OCSF 4001: Network Activity — network connection and traffic.
    NetworkActivity = 44001

    # OCSF 4002: HTTP Activity — HTTP connection and traffic.
    HttpActivity = 44002

    # OCSF 4003: DNS Activity — DNS queries and answers.
    DnsActivity = 44003

    # OCSF 4004: DHCP Activity — MAC-to-IP assignment.
    DhcpActivity = 44004

    # OCSF 4005: RDP Activity — Remote Desktop Protocol connections.
    RdpActivity = 44005

    # OCSF 4006: SMB Activity — Server Message Block resource sharing.
    SmbActivity = 44006

    # OCSF 4007: SSH Activity — Secure Shell remote connections.
    SshActivity = 44007

    # OCSF 4008: FTP Activity — file transfers between client and server.
    FtpActivity = 44008

    # OCSF 4009: Email Activity — email send, receive, and delivery actions.
    EmailActivity = 44009

    # OCSF 4010: Network File Activity — file activities traversing the network.
    NetworkFileActivity = 44010

    # OCSF 4011: Email File Activity — files attached to or embedded in emails.
    EmailFileActivity = 44011

    # OCSF 4012: Email URL Activity — URLs within an email.
    EmailUrlActivity = 44012

    # OCSF 4013: NTP Activity — clock synchronisation with an NTP server.
    NtpActivity = 44013

    # OCSF 4014: Tunnel Activity — secure tunnel establishment, teardown, renewal.
    TunnelActivity = 44014

    # -------------------------------------------------------------------------
    # OCSF Category 5 — Discovery (OCSF 5001–5020 → BSM 45001–45020)
    # -------------------------------------------------------------------------

    # OCSF 5001: Device Inventory Info — device inventory data.
    DeviceInventoryInfo = 45001

    # OCSF 5002: Device Config State — device configuration and CIS Benchmark.
    DeviceConfigState = 45002

    # OCSF 5003: User Inventory Info — user inventory data.
    UserInventoryInfo = 45003

    # OCSF 5004: Operating System Patch State — OS patch installation.
    OsPatchState = 45004

    # OCSF 5006: Kernel Object Query — discovered kernel resources. (5005 unassigned)
    KernelObjectQuery = 45006

    # OCSF 5007: File Query — files present on the system.
    FileQuery = 45007

    # OCSF 5008: Folder Query — folders present on the system.
    FolderQuery = 45008

    # OCSF 5009: Admin Group Query — administrative group information.
    AdminGroupQuery = 45009

    # OCSF 5010: Job Query — scheduled job information.
    JobQuery = 45010

    # OCSF 5011: Module Query — loaded module information.
    ModuleQuery = 45011

    # OCSF 5012: Network Connection Query — active network connections.
    NetworkConnectionQuery = 45012

    # OCSF 5013: Networks Query — network adapter information.
    NetworksQuery = 45013

    # OCSF 5014: Peripheral Device Query — peripheral device information.
    PeripheralDeviceQuery = 45014

    # OCSF 5015: Process Query — running process information.
    ProcessQuery = 45015

    # OCSF 5016: Service Query — running service information.
    ServiceQuery = 45016

    # OCSF 5017: User Session Query — existing user session information.
    UserSessionQuery = 45017

    # OCSF 5018: User Query — user data discovered or searched.
    UserQuery = 45018

    # OCSF 5019: Device Config State Change — state changes impacting device security.
    DeviceConfigStateChange = 45019

    # OCSF 5020: Software Inventory Info — device software inventory.
    SoftwareInventoryInfo = 45020

    # -------------------------------------------------------------------------
    # OCSF Category 6 — Application Activity (OCSF 6001–6007 → BSM 46001–46007)
    # -------------------------------------------------------------------------

    # OCSF 6001: Web Resources Activity — actions on web resources.
    WebResourcesActivity = 46001

    # OCSF 6002: Application Lifecycle — install, remove, start, stop of app/service.
    ApplicationLifecycle = 46002

    # OCSF 6003: API Activity — general CRUD API operations.
    ApiActivity = 46003

    # OCSF 6004: Web Resource Access Activity — HTTP access attempts to web resources.
    WebResourceAccessActivity = 46004

    # OCSF 6005: Datastore Activity — activities affecting datastores or their data.
    DatastoreActivity = 46005

    # OCSF 6006: File Hosting Activity — file management and sharing application actions.
    FileHostingActivity = 46006

    # OCSF 6007: Scan Activity — scan job start, completion, and results.
    ScanActivity = 46007

    # -------------------------------------------------------------------------
    # OCSF Category 7 — Remediation (OCSF 7001–7004 → BSM 47001–47004)
    # -------------------------------------------------------------------------

    # OCSF 7001: Remediation Activity — remediating compromised devices or networks.
    RemediationActivity = 47001

    # OCSF 7002: File Remediation Activity — remediating files.
    FileRemediationActivity = 47002

    # OCSF 7003: Process Remediation Activity — remediating processes.
    ProcessRemediationActivity = 47003

    # OCSF 7004: Network Remediation Activity — remediating computer networks.
    NetworkRemediationActivity = 47004

    # Returns the single `/etc/security/audit_event` line for this event.
    #
    # Format: `number:name:description:class`
    #
    # ```
    # FreeBSD::Audit::AUE::Authentication.audit_event_line
    # # => "43002:OCSF_authentication:OCSF Authentication event:aa"
    # ```
    def audit_event_line : String
      name = "OCSF_#{to_s.gsub(/([A-Z]+)([A-Z][a-z])/, "\\1_\\2").gsub(/([a-z\d])([A-Z])/, "\\1_\\2").downcase}"
      desc = "OCSF #{to_s.gsub(/([A-Z]+)([A-Z][a-z])/, "\\1_\\2").gsub(/([a-z\d])([A-Z])/, "\\1_\\2").gsub('_', ' ')} event"
      "#{value}:#{name}:#{desc}:aa"
    end

    # Generates `/etc/security/audit_event` lines for the given events.
    #
    # Pass a subset of `AUE` values to generate only those lines, or call
    # without arguments to generate lines for every mapped OCSF event
    # (i.e. all values except `None`).
    #
    # ```
    # puts FreeBSD::Audit::AUE.audit_event_config(
    #   FreeBSD::Audit::AUE::Authentication,
    #   FreeBSD::Audit::AUE::FileSystemActivity,
    # )
    # ```
    #
    # Output:
    # ```
    # # /etc/security/audit_event  (format: number:name:description:class)
    # 43002:OCSF_authentication:OCSF Authentication event:aa
    # 41001:OCSF_file_system_activity:OCSF File System Activity event:aa
    # ```
    def self.audit_event_config : String
      lines = values.reject(&.none?).map(&.audit_event_line)
      "# /etc/security/audit_event  (format: number:name:description:class)\n#{lines.join('\n')}"
    end

    def self.audit_event_config(*events : AUE) : String
      lines = events.to_a.map(&.audit_event_line)
      "# /etc/security/audit_event  (format: number:name:description:class)\n#{lines.join('\n')}"
    end
  end
end
