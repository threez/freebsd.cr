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
end

describe FreeBSD::Pkg::LoadFlags do
  it "coerces symbols and arrays to a folded LoadFlags" do
    FreeBSD::Pkg::LoadFlags.from(:deps).should eq(FreeBSD::Pkg::LoadFlags::Deps)
    FreeBSD::Pkg::LoadFlags.from(:shlibs_required).should eq(FreeBSD::Pkg::LoadFlags::ShlibsRequired)
    FreeBSD::Pkg::LoadFlags.from(FreeBSD::Pkg::LoadFlags::Categories).should eq(FreeBSD::Pkg::LoadFlags::Categories)
    FreeBSD::Pkg::LoadFlags.from([:deps, :annotations]).should eq(FreeBSD::Pkg::LoadFlags::Deps | FreeBSD::Pkg::LoadFlags::Annotations)
    FreeBSD::Pkg::LoadFlags.from([:deps, FreeBSD::Pkg::LoadFlags::Files]).should eq(FreeBSD::Pkg::LoadFlags::Deps | FreeBSD::Pkg::LoadFlags::Files)
  end

  it "raises ArgumentError naming an unknown symbol" do
    expect_raises(ArgumentError) { FreeBSD::Pkg::LoadFlags.from(:bogus) }
  end
end

describe FreeBSD::Pkg::InitFlags do
  it "coerces symbols and arrays to a folded InitFlags" do
    FreeBSD::Pkg::InitFlags.from(:use_ipv4).should eq(FreeBSD::Pkg::InitFlags::UseIpv4)
    FreeBSD::Pkg::InitFlags.from(FreeBSD::Pkg::InitFlags::UseIpv6).should eq(FreeBSD::Pkg::InitFlags::UseIpv6)
    FreeBSD::Pkg::InitFlags.from([:use_ipv4, :use_ipv6]).should eq(FreeBSD::Pkg::InitFlags::UseIpv4 | FreeBSD::Pkg::InitFlags::UseIpv6)
  end

  it "raises ArgumentError naming an unknown symbol" do
    expect_raises(ArgumentError) { FreeBSD::Pkg::InitFlags.from(:bogus) }
  end
end

describe FreeBSD::Pkg do
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

    it_on_pkg "init accepts a single symbol flag" do
      FreeBSD::Pkg.init(flags: :use_ipv4) do
        FreeBSD::Pkg.initialized?.should be_true
      end
    end

    # Note: InitFlags only has UseIpv4/UseIpv6, and libpkg's pkg_ini rejects
    # both set together (EPKG_FATAL) — there's no valid multi-flag
    # combination to exercise live here. The array-coercion mechanism
    # itself (InitFlags.from(Enumerable)) is covered by the pure unit spec
    # above; this just proves an Array literal type-checks against init's
    # widened `flags:` parameter.
    it_on_pkg "init accepts an array containing a single symbol flag" do
      FreeBSD::Pkg.init(flags: [:use_ipv4]) do
        FreeBSD::Pkg.initialized?.should be_true
      end
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
