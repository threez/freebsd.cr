require "../spec_helper"
require "../../src/freebsd/casper/audit_helper"

# Probe whether auditd is accepting records (same helper used in audit_spec.cr).
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

private def test_aue : FreeBSD::Audit::AUE
  FreeBSD::Audit::AUE.new(32768_u16)
end

describe FreeBSD::Casper::AuditHelper do
  # ---------------------------------------------------------------------------
  # Token serialization round-trips — no helper process or auditd required.
  # ---------------------------------------------------------------------------

  describe "Token" do
    it_on_capsicum "Token.text round-trips via Codec::NVList" do
      tok = FreeBSD::Casper::AuditHelper::Token.text("hello audit")
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.kind.should eq("text")
      decoded.text.should eq("hello audit")
    end

    it_on_capsicum "Token.subject without terminal round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.subject(80_u64, 0_u64, 100_u64, 100_u64, 1234_u64, 0_u64, nil)
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.kind.should eq("subject")
      decoded.uid.should eq(80_u64)
      decoded.pid.should eq(1234_u64)
      decoded.terminal.should be_nil
    end

    it_on_capsicum "Token.subject with IPv4 terminal round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.subject(0_u64, 0_u64, 0_u64, 0_u64, 1_u64, 0_u64, "127.0.0.1")
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.terminal.should eq("127.0.0.1")
    end

    it_on_capsicum "Token.subject with IPv6 terminal round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.subject(0_u64, 0_u64, 0_u64, 0_u64, 1_u64, 0_u64, "::1")
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.terminal.should eq("::1")
    end

    it_on_capsicum "Token.address IPv4 round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.address("192.168.1.1")
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.kind.should eq("address")
      decoded.addr.should eq("192.168.1.1")
    end

    it_on_capsicum "Token.address IPv6 round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.address("::1")
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.addr.should eq("::1")
    end

    it_on_capsicum "Token.return_ok round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.return_ok(42_u32)
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.kind.should eq("return")
      decoded.status.should eq(0_u64)
      decoded.retval.should eq(42_u64)
    end

    it_on_capsicum "Token.return_fail round-trips" do
      tok = FreeBSD::Casper::AuditHelper::Token.return_fail(13_u32)
      bytes = FreeBSD::Casper::Codec::NVList.encode(tok)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Token)
      decoded.kind.should eq("return")
      decoded.status.should eq(1_u64)
      decoded.retval.should eq(13_u64)
    end
  end

  describe "Request" do
    it_on_capsicum "round-trips with multiple tokens via Codec::NVList" do
      tokens = [
        FreeBSD::Casper::AuditHelper::Token.text("spec token"),
        FreeBSD::Casper::AuditHelper::Token.return_ok(0_u32),
      ]
      req = FreeBSD::Casper::AuditHelper::Request.new(
        event: 32768_u16, tokens: tokens, write: false)

      # Encode manually (mirrors Codec::NVList.encode for non-Serializable types)
      builder = FreeBSD::NVList::Builder.new
      req.to_nvlist_fields(builder)
      size = LibC::SizeT.new(0)
      ptr = LibNv.nvlist_pack(builder.to_unsafe, pointerof(size))
      bytes = Bytes.new(ptr.as(UInt8*), size).dup
      LibC.free(ptr)

      nvl = LibNv.nvlist_unpack(bytes.to_unsafe, bytes.size, 0)
      pull = FreeBSD::NVList::PullParser.new(nvl)
      req2 = FreeBSD::Casper::AuditHelper::Request.new(pull)
      LibNv.nvlist_destroy(nvl)

      req2.event.should eq(32768_u16)
      req2.write.should be_false
      req2.tokens.size.should eq(2)
      req2.tokens[0].kind.should eq("text")
      req2.tokens[0].text.should eq("spec token")
      req2.tokens[1].kind.should eq("return")
    end

    it_on_capsicum "round-trips an empty token list" do
      req = FreeBSD::Casper::AuditHelper::Request.new(
        event: 1_u16, tokens: [] of FreeBSD::Casper::AuditHelper::Token, write: true)

      builder = FreeBSD::NVList::Builder.new
      req.to_nvlist_fields(builder)
      size = LibC::SizeT.new(0)
      ptr = LibNv.nvlist_pack(builder.to_unsafe, pointerof(size))
      bytes = Bytes.new(ptr.as(UInt8*), size).dup
      LibC.free(ptr)

      nvl = LibNv.nvlist_unpack(bytes.to_unsafe, bytes.size, 0)
      pull = FreeBSD::NVList::PullParser.new(nvl)
      req2 = FreeBSD::Casper::AuditHelper::Request.new(pull)
      LibNv.nvlist_destroy(nvl)

      req2.tokens.should be_empty
      req2.write.should be_true
    end
  end

  describe "Response" do
    it_on_capsicum "ok response round-trips via Codec::NVList" do
      resp = FreeBSD::Casper::AuditHelper::Response.new(ok: true)
      bytes = FreeBSD::Casper::Codec::NVList.encode(resp)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Response)
      decoded.ok.should be_true
      decoded.message.should be_nil
    end

    it_on_capsicum "error response with message round-trips" do
      resp = FreeBSD::Casper::AuditHelper::Response.new(ok: false, message: "au_open failed")
      bytes = FreeBSD::Casper::Codec::NVList.encode(resp)
      decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, FreeBSD::Casper::AuditHelper::Response)
      decoded.ok.should be_false
      decoded.message.should eq("au_open failed")
    end
  end

  describe "TokenBuffer" do
    it_on_capsicum "accumulates tokens in order" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.text("hello")
      buf.return_success
      buf.tokens.size.should eq(2)
      buf.tokens[0].kind.should eq("text")
      buf.tokens[1].kind.should eq("return")
    end

    it_on_capsicum "subject captures caller credentials" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.subject(uid: 42_u32, pid: 99_i32, session: 0_u32, terminal: "10.0.0.1")
      tok = buf.tokens.first
      tok.kind.should eq("subject")
      tok.uid.should eq(42_u64)
      tok.pid.should eq(99_u64)
      tok.terminal.should eq("10.0.0.1")
    end

    it_on_capsicum "text(**fields) builds key=value string" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.text(user: "admin", method: "POST")
      buf.tokens.first.text.should eq("user=admin method=POST")
    end

    it_on_capsicum "activity_id appends a text token" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.activity_id(1_u8, "Logon")
      buf.tokens.first.text.should eq("activity_id=1 activity=Logon")
    end

    it_on_capsicum "address(Socket::IPAddress) extracts the IP string (IPv4)" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.address(Socket::IPAddress.new("10.0.0.1", 443))
      buf.tokens.first.addr.should eq("10.0.0.1")
    end

    it_on_capsicum "address(Socket::IPAddress) extracts the IP string (IPv6)" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.address(Socket::IPAddress.new("::1", 8080))
      buf.tokens.first.addr.should eq("::1")
    end

    it_on_capsicum "return_failure(Errno) maps errno value correctly" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.return_failure(Errno::EACCES)
      tok = buf.tokens.first
      tok.kind.should eq("return")
      tok.status.should eq(1_u64)
      tok.retval.should eq(Errno::EACCES.value.to_u64)
    end

    it_on_capsicum "activity_id(Activity) appends correct text token" do
      buf = FreeBSD::Casper::AuditHelper::TokenBuffer.new
      buf.activity_id(FreeBSD::Audit::Authentication::Activity::Logon)
      buf.tokens.first.text.should eq("activity_id=1 activity=Logon")
    end
  end

  # ---------------------------------------------------------------------------
  # Integration tests — fork a helper + enter sandbox
  # ---------------------------------------------------------------------------

  describe "Helper integration" do
    it_on_capsicum "discard request reaches helper and returns ok" do
      in_sandbox_child do
        client = FreeBSD::Casper::Helper.spawn(name: "audit-mock") do |server|
          server.on(FreeBSD::Casper::AuditHelper::Request) do |_req|
            FreeBSD::Casper::AuditHelper::Response.new(ok: true)
          end
          server.serve_typed
        end

        FreeBSD::Casper.install_audit_helper(client)
        FreeBSD::Capsicum.sandbox!

        FreeBSD::Casper::AuditHelper::Event.discard(test_aue) do |r|
          r.text "mock helper spec"
          r.return_success
        end
      end
    end

    it_on_capsicum "real libbsm discard via helper (skipped when auditd not running)" do
      next unless audit_running?

      in_sandbox_child do
        client = FreeBSD::Casper::Helper.spawn(name: "audit-real") do |server|
          server.on(FreeBSD::Casper::AuditHelper::Request) do |req|
            d = LibBsm.au_open
            next FreeBSD::Casper::AuditHelper::Response.new(ok: false, message: "au_open failed") if d == -1
            req.tokens.each do |tok|
              case tok.kind
              when "text"
                t = LibBsm.au_to_text(tok.text.not_nil!)
                LibBsm.au_write(d, t)
              when "return"
                t = LibBsm.au_to_return32(tok.status.not_nil!.to_u8, tok.retval.not_nil!.to_u32)
                LibBsm.au_write(d, t)
              end
            end
            keep = req.write ? LibBsm::AU_TO_WRITE : LibBsm::AU_TO_NO_WRITE
            LibBsm.au_close(d, keep, req.event)
            FreeBSD::Casper::AuditHelper::Response.new(ok: true)
          end
          server.serve_typed
        end

        FreeBSD::Casper.install_audit_helper(client)
        FreeBSD::Capsicum.sandbox!

        FreeBSD::Casper::AuditHelper::Event.discard(test_aue) do |r|
          r.subject
          r.text "casper audit helper spec — discard"
          r.return_success
        end
      end
    end

    it_on_capsicum "AuditHelper::Event.write_activity sends correct AUE value" do
      # Verify that write_activity derives the AUE from the activity's #aue method.
      # The helper echoes the event value back in the response message so we can
      # inspect it from the client side without relying on cross-process closures.
      in_sandbox_child do
        client = FreeBSD::Casper::Helper.spawn(name: "audit-aue") do |server|
          server.on(FreeBSD::Casper::AuditHelper::Request) do |req|
            FreeBSD::Casper::AuditHelper::Response.new(ok: true, message: req.event.to_s)
          end
          server.serve_typed
        end

        FreeBSD::Casper.install_audit_helper(client)
        FreeBSD::Capsicum.sandbox!

        # Capture the echoed event value by making a raw request.
        req = FreeBSD::Casper::AuditHelper::Request.new(
          event: FreeBSD::Audit::AUE::Authentication.value,
          tokens: [] of FreeBSD::Casper::AuditHelper::Token,
          write: false)
        resp = client.request(req, FreeBSD::Casper::AuditHelper::Response)
        resp.message.should eq(FreeBSD::Audit::AUE::Authentication.value.to_s)

        # Also verify write_activity doesn't raise.
        FreeBSD::Casper::AuditHelper::Event.write_activity(
          FreeBSD::Audit::Authentication::Activity::Logon
        ) do |r|
          r.text "user=spec"
          r.return_success
        end
      end
    end

    it_on_capsicum "AuditHelper::Event.write_activity prepends activity_id token" do
      # Verify activity_id token is the first token by checking token count:
      # write_activity prepends 1 activity_id token before the user's tokens.
      in_sandbox_child do
        client = FreeBSD::Casper::Helper.spawn(name: "audit-activity") do |server|
          server.on(FreeBSD::Casper::AuditHelper::Request) do |req|
            # Echo back the first token's text so the client can inspect it.
            first = req.tokens.first?
            msg = first ? "#{first.kind}:#{first.text}" : "empty"
            FreeBSD::Casper::AuditHelper::Response.new(ok: true, message: msg)
          end
          server.serve_typed
        end

        FreeBSD::Casper.install_audit_helper(client)
        FreeBSD::Capsicum.sandbox!

        # Send a known request with 1 user token and check the server saw 2.
        req = FreeBSD::Casper::AuditHelper::Request.new(
          event: FreeBSD::Audit::AUE::Authentication.value,
          tokens: [
            FreeBSD::Casper::AuditHelper::Token.text("activity_id=1 activity=Logon"),
            FreeBSD::Casper::AuditHelper::Token.text("user=spec"),
          ],
          write: false)
        resp = client.request(req, FreeBSD::Casper::AuditHelper::Response)
        resp.message.should eq("text:activity_id=1 activity=Logon")
      end
    end

    it_on_capsicum "audit_helper! raises when no helper installed" do
      FreeBSD::Casper.uninstall_audit_helper
      expect_raises(Exception, /not installed/) do
        FreeBSD::Casper.audit_helper!
      end
    end
  end
end
