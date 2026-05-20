require "../spec_helper"

describe FreeBSD::Capsicum::Capability::Rights do
  it_on_capsicum "constructs a valid rights set" do
    r = FreeBSD::Capsicum::Capability::Rights.new(
      FreeBSD::Capsicum::Capability::Right::Read,
      FreeBSD::Capsicum::Capability::Right::Fstat,
    )
    r.valid?.should be_true
    r.includes?(FreeBSD::Capsicum::Capability::Right::Read).should be_true
    r.includes?(FreeBSD::Capsicum::Capability::Right::Write).should be_false
  end

  it_on_capsicum "round-trips through cap_rights_limit/get on a real fd" do
    File.open("/etc/hosts", "r") do |file|
      FreeBSD::Capsicum::Capability::Rights
        .new(FreeBSD::Capsicum::Capability::Right::Read, FreeBSD::Capsicum::Capability::Right::Fstat)
        .apply_to(file)

      got = FreeBSD::Capsicum::Capability::Rights.of(file)
      got.includes?(FreeBSD::Capsicum::Capability::Right::Read).should be_true
      got.includes?(FreeBSD::Capsicum::Capability::Right::Write).should be_false
    end
  end
end

describe "FreeBSD::Capsicum.sandbox" do
  it_on_capsicum "enters capability mode" do
    in_sandbox_child do
      FreeBSD::Capsicum.sandbox!
      FreeBSD::Capsicum.sandboxed?.should be_true
    end
  end

  it_on_capsicum "blocks global namespace access after sandboxing" do
    in_sandbox_child do
      FreeBSD::Capsicum.sandbox!
      expect_raises(File::Error) { File.open("/etc/hosts", "r") { } }
    end
  end
end
