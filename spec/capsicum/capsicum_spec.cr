require "../spec_helper"

describe FreeBSD::Capsicum do
  it "reports platform support" do
    FreeBSD::Capsicum::SUPPORTED.should eq(CAPSICUM_OS)
  end

  it "raises UnsupportedPlatformError off-FreeBSD" do
    unless CAPSICUM_OS
      expect_raises(FreeBSD::Capsicum::UnsupportedPlatformError) { FreeBSD::Capsicum.sandbox! }
    end
  end
end
