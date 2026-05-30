require "../spec_helper"

describe FreeBSD::Pkg do
  it "reports SUPPORTED correctly" do
    FreeBSD::Pkg::SUPPORTED.should eq({{ flag?(:freebsd) }})
  end

  it "LoadFlags::None has value 0 (PKG_LOAD_BASIC)" do
    FreeBSD::Pkg::LoadFlags::None.value.should eq(0_u32)
  end

  it "LoadFlags::Deps has value 1" do
    FreeBSD::Pkg::LoadFlags::Deps.value.should eq(1_u32)
  end

  it "LoadFlags::Annotations has value 4096" do
    FreeBSD::Pkg::LoadFlags::Annotations.value.should eq(4096_u32)
  end

  it "LoadFlags can be combined with |" do
    combined = FreeBSD::Pkg::LoadFlags::Deps | FreeBSD::Pkg::LoadFlags::Files
    combined.value.should eq(5_u32)
  end

  describe "on non-FreeBSD platforms" do
    unless FreeBSD::Pkg::SUPPORTED
      it "init! raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Pkg::UnsupportedPlatformError) do
          FreeBSD::Pkg.init!
        end
      end
    end
  end

  describe "on FreeBSD" do
    it_on_pkg "init block: initialized? is true inside, false after" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg.initialized?.should be_true
      end
      FreeBSD::Pkg.initialized?.should be_false
    end

    it_on_pkg "init! and shutdown work" do
      FreeBSD::Pkg.init!
      FreeBSD::Pkg.initialized?.should be_true
      FreeBSD::Pkg.shutdown
      FreeBSD::Pkg.initialized?.should be_false
    end

    it_on_pkg "version_cmp returns 0 for equal versions" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg.version_cmp("1.0", "1.0").should eq(0)
      end
    end

    it_on_pkg "version_cmp returns negative when a < b" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg.version_cmp("1.0", "2.0").should be < 0
      end
    end

    it_on_pkg "version_cmp returns positive when a > b" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg.version_cmp("2.0", "1.0").should be > 0
      end
    end
  end
end
