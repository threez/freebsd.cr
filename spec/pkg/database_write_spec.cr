require "../spec_helper"

describe FreeBSD::Pkg::Database do
  describe "#with_advisory_lock" do
    it_on_pkg_write "yields without error" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          yielded = false
          db.with_advisory_lock { yielded = true }
          yielded.should be_true
        end
      end
    end
  end

  describe "#with_exclusive_lock" do
    it_on_pkg_write "yields without error" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          yielded = false
          db.with_exclusive_lock { yielded = true }
          yielded.should be_true
        end
      end
    end
  end

  describe "#transaction" do
    it_on_pkg_write "begin/commit works with an empty block" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          db.with_advisory_lock do
            db.transaction do
              # empty transaction — verifies no crash
            end
          end
        end
      end
    end
  end

  describe "annotation CRUD" do
    it_on_pkg_write "add_annotation / delete_annotation round-trip on 'pkg'" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query("pkg",
            match: FreeBSD::Pkg::MatchType::Exact,
            flags: FreeBSD::Pkg::LoadFlags::Annotations)
          next if pkgs.empty?
          pkg = pkgs.first
          db.with_advisory_lock do
            db.add_annotation(pkg, "freebsd-cr-test-tag", "test-value")
            db.delete_annotation(pkg, "freebsd-cr-test-tag")
          end
        end
      end
    end
  end

  describe "#lock / #unlock" do
    it_on_pkg_write "lock and unlock 'pkg' without leaving it locked" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query("pkg", match: FreeBSD::Pkg::MatchType::Exact)
          next if pkgs.empty?
          pkg = pkgs.first
          db.with_advisory_lock do
            db.lock(pkg)
            db.unlock(pkg)
          end
        end
      end
    end
  end

  describe "#set_vital" do
    it_on_pkg_write "set_vital true/false round-trip on 'pkg'" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query("pkg", match: FreeBSD::Pkg::MatchType::Exact)
          next if pkgs.empty?
          pkg = pkgs.first
          original_vital = pkg.vital?
          db.with_advisory_lock do
            db.set_vital(pkg, !original_vital)
            db.set_vital(pkg, original_vital)
          end
        end
      end
    end
  end

  describe "#set_automatic" do
    it_on_pkg_write "set_automatic true/false round-trip on 'pkg'" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          pkgs = db.query("pkg", match: FreeBSD::Pkg::MatchType::Exact)
          next if pkgs.empty?
          pkg = pkgs.first
          original_auto = pkg.automatic?
          db.with_advisory_lock do
            db.set_automatic(pkg, !original_auto)
            db.set_automatic(pkg, original_auto)
          end
        end
      end
    end
  end
end
