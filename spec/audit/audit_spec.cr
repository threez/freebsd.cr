require "../spec_helper"
require "../../src/freebsd/audit"

AUDIT_OS = FreeBSD::Audit::SUPPORTED

# Probe whether auditd is accepting records by opening and immediately
# discarding a record. Returns false on non-FreeBSD or when auditd is down.
private def audit_running? : Bool
  {% if flag?(:freebsd) || flag?(:dragonfly) %}
    d = LibBsm.au_open
    return false if d == -1
    LibBsm.au_close(d, LibBsm::AU_TO_NO_WRITE, 0_u16)
    true
  {% else %}
    false
  {% end %}
end

# A placeholder event value for specs — using the first value in the
# application-defined range.
private def test_event : FreeBSD::Audit::AUE
  FreeBSD::Audit::AUE.new(32768_u16)
end

describe FreeBSD::Audit do
  it "reports SUPPORTED correctly" do
    FreeBSD::Audit::SUPPORTED.should eq(AUDIT_OS)
  end

  describe "on non-FreeBSD platforms" do
    unless AUDIT_OS
      it "Event.write raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Audit::UnsupportedPlatformError) do
          FreeBSD::Audit::Event.write(test_event) { }
        end
      end

      it "Event.discard raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Audit::UnsupportedPlatformError) do
          FreeBSD::Audit::Event.discard(test_event) { }
        end
      end
    end
  end

  describe "on FreeBSD" do
    it_on_capsicum "Event.write raises RecordOpenError when audit not running" do
      next if audit_running?
      expect_raises(FreeBSD::Audit::RecordOpenError) do
        FreeBSD::Audit::Event.write(test_event) { }
      end
    end

    it_on_capsicum "Event.discard raises RecordOpenError when audit not running" do
      next if audit_running?
      expect_raises(FreeBSD::Audit::RecordOpenError) do
        FreeBSD::Audit::Event.discard(test_event) { }
      end
    end

    it_on_capsicum "Event.discard succeeds with text token when audit running" do
      next unless audit_running?
      write_failures = -1
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.text "spec test — FreeBSD::Audit"
        write_failures = r.write_failures
      end
      write_failures.should eq(0)
    end

    it_on_capsicum "Event.discard succeeds with subject and return tokens" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.subject uid: LibC.getuid.to_u32, pid: Process.pid.to_i32, session: 0_u32
        r.text "subject+return spec"
        r.return_success
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.text accepts key=value named fields" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.text(user: "admin", method: "POST", path: "/login")
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.address accepts IPv4" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.address "192.168.1.1"
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.address accepts IPv6" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.address "::1"
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.address raises on invalid address" do
      next unless audit_running?
      expect_raises(FreeBSD::Audit::InvalidArgumentError) do
        FreeBSD::Audit::Event.discard(test_event) do |r|
          r.address "not-an-ip"
        end
      end
    end

    it_on_capsicum "Record.address accepts Socket::IPAddress (IPv4)" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.address Socket::IPAddress.new("10.0.0.1", 443)
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.address accepts Socket::IPAddress (IPv6)" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.address Socket::IPAddress.new("::1", 8080)
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.return_failure accepts Errno constant" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.return_failure Errno::EACCES
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.activity_id accepts a typed Activity value" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.activity_id FreeBSD::Audit::Authentication::Activity::Logon
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.subject accepts IPv4 terminal" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.subject uid: LibC.getuid.to_u32, terminal: "127.0.0.1"
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Record.subject accepts IPv6 terminal" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard(test_event) do |r|
        r.subject uid: LibC.getuid.to_u32, terminal: "::1"
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "Event.write discards record when block raises" do
      next unless audit_running?
      expect_raises(Exception, "intentional") do
        FreeBSD::Audit::Event.write(test_event) do |r|
          r.text "before raise"
          raise "intentional"
        end
      end
    end

    it_on_capsicum "Event.write commits record when block succeeds" do
      next unless audit_running?
      # Just verify no exception is raised — praudit verification is manual.
      FreeBSD::Audit::Event.write(test_event) do |r|
        r.text "spec integration event"
        r.return_success
      end
    end
  end

  describe "AUE — direct OCSF mapping (ocsf_uid + 40000)" do
    it "Authentication maps to 43002" do
      FreeBSD::Audit::AUE::Authentication.value.should eq(43002_u16)
    end

    it "FileSystemActivity maps to 41001" do
      FreeBSD::Audit::AUE::FileSystemActivity.value.should eq(41001_u16)
    end

    it "FileRemediationActivity maps to 47002" do
      FreeBSD::Audit::AUE::FileRemediationActivity.value.should eq(47002_u16)
    end

    it "all values are in the application range 40000–65535" do
      FreeBSD::Audit::AUE.each do |_, v|
        next if v == 0_u16 # None
        v.should be >= 40000_u16
      end
    end

    describe "#audit_event_line" do
      it "formats Authentication correctly" do
        FreeBSD::Audit::AUE::Authentication.audit_event_line
          .should eq("43002:OCSF_authentication:OCSF Authentication event:aa")
      end

      it "formats FileSystemActivity with underscores" do
        FreeBSD::Audit::AUE::FileSystemActivity.audit_event_line
          .should eq("41001:OCSF_file_system_activity:OCSF File System Activity event:aa")
      end

      it "formats DnsActivity correctly" do
        FreeBSD::Audit::AUE::DnsActivity.audit_event_line
          .should eq("44003:OCSF_dns_activity:OCSF Dns Activity event:aa")
      end
    end

    describe ".audit_event_config" do
      it "returns a header comment line" do
        config = FreeBSD::Audit::AUE.audit_event_config(FreeBSD::Audit::AUE::Authentication)
        config.should start_with("# /etc/security/audit_event")
      end

      it "includes selected events only" do
        config = FreeBSD::Audit::AUE.audit_event_config(
          FreeBSD::Audit::AUE::Authentication,
          FreeBSD::Audit::AUE::FileSystemActivity,
        )
        config.should contain("43002:OCSF_authentication")
        config.should contain("41001:OCSF_file_system_activity")
        config.should_not contain("44003:")
      end

      it "generates all events when called with no arguments" do
        config = FreeBSD::Audit::AUE.audit_event_config
        FreeBSD::Audit::AUE.each do |_, v|
          next if v == 0_u16
          config.should contain("#{v}:")
        end
      end
    end
  end

  describe "Activity enums" do
    it "Authentication::Activity::Logon.aue returns AUE::Authentication" do
      FreeBSD::Audit::Authentication::Activity::Logon.aue.should eq(FreeBSD::Audit::AUE::Authentication)
    end

    it "Authentication::Activity::Logon has value 1" do
      FreeBSD::Audit::Authentication::Activity::Logon.value.should eq(1_u8)
    end

    it "FileSystemActivity::Activity::Create has value 1" do
      FreeBSD::Audit::FileSystemActivity::Activity::Create.value.should eq(1_u8)
    end

    it "ProcessActivity::Activity::Launch.aue returns AUE::ProcessActivity" do
      FreeBSD::Audit::ProcessActivity::Activity::Launch.aue.should eq(FreeBSD::Audit::AUE::ProcessActivity)
    end

    it "ApiActivity::Activity::Delete.aue returns AUE::ApiActivity" do
      FreeBSD::Audit::ApiActivity::Activity::Delete.aue.should eq(FreeBSD::Audit::AUE::ApiActivity)
    end

    it "all Activity enums have Unknown = 0 and Other = 99" do
      FreeBSD::Audit::Authentication::Activity::Unknown.value.should eq(0_u8)
      FreeBSD::Audit::Authentication::Activity::Other.value.should eq(99_u8)
      FreeBSD::Audit::FileSystemActivity::Activity::Unknown.value.should eq(0_u8)
      FreeBSD::Audit::FileSystemActivity::Activity::Other.value.should eq(99_u8)
    end
  end

  describe "Event.write_activity / discard_activity" do
    it_on_capsicum "discard_activity writes activity_id token without failures" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard_activity(FreeBSD::Audit::Authentication::Activity::Logon) do |r|
        r.text "user=spec"
        r.return_failure
        r.write_failures.should eq(0)
      end
    end

    it_on_capsicum "write_activity commits record for Authentication::Logon" do
      next unless audit_running?
      FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::Authentication::Activity::Logon) do |r|
        r.subject
        r.text "user=spec"
        r.return_success
      end
    end

    it_on_capsicum "discard_activity works for FileSystemActivity::Create" do
      next unless audit_running?
      FreeBSD::Audit::Event.discard_activity(FreeBSD::Audit::FileSystemActivity::Activity::Create) do |r|
        r.text "path=/tmp/test"
        r.return_success
        r.write_failures.should eq(0)
      end
    end
  end
end
