require "../spec_helper"

# Opens a local DB, fetches the 'pkg' package with all flags, and yields it.
private def with_pkg_package(flags : FreeBSD::Pkg::LoadFlags = FreeBSD::Pkg::LoadFlags::None, &)
  FreeBSD::Pkg.init do
    FreeBSD::Pkg::Database.open do |db|
      pkgs = db.query("pkg",
        match: FreeBSD::Pkg::MatchType::Exact,
        flags: flags)
      yield pkgs.first if pkgs.first?
    end
  end
end

describe FreeBSD::Pkg::Package do
  describe "string attributes" do
    it_on_pkg "name is non-empty" do
      with_pkg_package { |pkg| pkg.name.should eq("pkg") }
    end

    it_on_pkg "version is non-empty" do
      with_pkg_package { |pkg| pkg.version.should_not be_empty }
    end

    it_on_pkg "origin is non-empty" do
      with_pkg_package { |pkg| pkg.origin.should_not be_empty }
    end

    it_on_pkg "prefix starts with /" do
      with_pkg_package { |pkg| pkg.prefix.should start_with("/") }
    end

    it_on_pkg "abi is non-empty" do
      with_pkg_package { |pkg| pkg.abi.should_not be_empty }
    end
  end

  describe "integer attributes" do
    it_on_pkg "installed_size is positive" do
      with_pkg_package { |pkg| pkg.installed_size.should be > 0_i64 }
    end

    it_on_pkg "installed_at is a Time" do
      with_pkg_package { |pkg| pkg.installed_at.should be_a(Time) }
    end
  end

  describe "boolean attributes" do
    it_on_pkg "automatic? is a Bool" do
      with_pkg_package { |pkg| pkg.automatic?.should be_a(Bool) }
    end

    it_on_pkg "locked? is a Bool" do
      with_pkg_package { |pkg| pkg.locked?.should be_a(Bool) }
    end

    it_on_pkg "vital? is a Bool" do
      with_pkg_package { |pkg| pkg.vital?.should be_a(Bool) }
    end
  end

  describe "#valid?" do
    it_on_pkg "returns a Bool" do
      with_pkg_package { |pkg| pkg.valid?.should be_a(Bool) }
    end
  end

  describe "#type" do
    it_on_pkg "is Installed for a locally installed package" do
      with_pkg_package do |pkg|
        pkg.type.should eq(FreeBSD::Pkg::Package::Type::Installed)
      end
    end
  end

  describe "stringlist attributes" do
    it_on_pkg "categories returns an Array(String)" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::Categories) do |pkg|
        pkg.categories.should be_a(Array(String))
      end
    end

    it_on_pkg "shlibs_required returns an Array(String)" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::ShlibsRequired) do |pkg|
        pkg.shlibs_required.should be_a(Array(String))
      end
    end
  end

  describe "annotations" do
    it_on_pkg "annotations returns a Hash(String, String)" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::Annotations) do |pkg|
        pkg.annotations.should be_a(Hash(String, String))
      end
    end
  end

  describe "#each_dependency" do
    it_on_pkg "yields Dependency instances" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::Deps) do |pkg|
        pkg.each_dependency do |dep|
          dep.name.should_not be_empty
          dep.should be_a(FreeBSD::Pkg::Dependency)
        end
      end
    end
  end

  describe "#each_file" do
    it_on_pkg "yields FileEntry instances" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::Files) do |pkg|
        count = 0
        pkg.each_file do |fe|
          fe.should be_a(FreeBSD::Pkg::FileEntry)
          count += 1
        end
        count.should be > 0
      end
    end
  end

  describe "#has_file?" do
    it_on_pkg "returns true for /usr/local/sbin/pkg" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::Files) do |pkg|
        pkg.has_file?("/usr/local/sbin/pkg").should be_true
      end
    end

    it_on_pkg "returns false for a non-existent path" do
      with_pkg_package(FreeBSD::Pkg::LoadFlags::Files) do |pkg|
        pkg.has_file?("/this/does/not/exist/at/all").should be_false
      end
    end
  end
end
