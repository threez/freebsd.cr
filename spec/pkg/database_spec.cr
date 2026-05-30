require "../spec_helper"

describe FreeBSD::Pkg::Database do
  describe "open / close" do
    it_on_pkg "opens and closes without error" do
      FreeBSD::Pkg.init do
        db = FreeBSD::Pkg::Database.open
        db.closed?.should be_false
        db.close
        db.closed?.should be_true
      end
    end

    it_on_pkg "block form closes automatically" do
      FreeBSD::Pkg.init do
        db_ref = nil
        FreeBSD::Pkg::Database.open do |db|
          db_ref = db
          db.closed?.should be_false
        end
        db_ref.not_nil!.closed?.should be_true
      end
    end

    it_on_pkg "opens in LocalReadonly mode" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::LocalReadonly) do |db|
          db.closed?.should be_false
        end
      end
    end
  end

  describe "#query" do
    it_on_pkg "returns at least one package when pattern is nil" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query
          pkgs.size.should be > 0
        end
      end
    end

    it_on_pkg "returns packages with non-empty names" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          db.query.each do |pkg|
            pkg.name.should_not be_empty
          end
        end
      end
    end

    it_on_pkg "exact match for 'pkg' returns exactly one result" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query("pkg", match: FreeBSD::Pkg::MatchType::Exact)
          pkgs.size.should eq(1)
          pkgs.first.name.should eq("pkg")
        end
      end
    end

    it_on_pkg "glob match for 'pkg*' returns at least one result" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query("pkg*", match: FreeBSD::Pkg::MatchType::Glob)
          pkgs.size.should be >= 1
        end
      end
    end
  end

  describe "#each" do
    it_on_pkg "enumerates at least one package" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          count = 0
          db.each { count += 1 }
          count.should be > 0
        end
      end
    end
  end

  describe "#installed?" do
    it_on_pkg "returns true for 'pkg' (always installed)" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          db.installed?("pkg").should be_true
        end
      end
    end

    it_on_pkg "returns false for a non-existent package name" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          db.installed?("this-package-does-not-exist-zzzz").should be_false
        end
      end
    end
  end

  describe "#which" do
    it_on_pkg "returns a Package or nil for /usr/local/sbin/pkg" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          result = db.which("/usr/local/sbin/pkg")
          if result
            result.name.should_not be_empty
          end
          # nil is also valid (path may not be in db on minimal installs)
          result.is_a?(FreeBSD::Pkg::Package | Nil).should be_true
        end
      end
    end
  end

  describe "#requiring_shlib / #providing_shlib" do
    it_on_pkg "requiring_shlib returns an Array" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          result = db.requiring_shlib("libz.so.6")
          result.is_a?(Array).should be_true
        end
      end
    end

    it_on_pkg "providing_shlib returns an Array" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          result = db.providing_shlib("libz.so.6")
          result.is_a?(Array).should be_true
        end
      end
    end
  end
end
