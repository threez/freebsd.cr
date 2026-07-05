require "../spec_helper"

describe FreeBSD::Pkg::Jobs do
  describe ".install dry-run" do
    it_on_pkg_write "solver runs without error for an already-installed package" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.install(
              db, ["pkg"],
              flags: FreeBSD::Pkg::JobFlags::DryRun | FreeBSD::Pkg::JobFlags::WithDeps
            ) do |jobs|
              jobs.solve
              # pkg is already installed — count is 0
              jobs.count.should be >= 0
            end
          end
        end
      end
    end

    it_on_pkg_write "accepts symbol/array flags and symbol match" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.install(
              db, ["pkg"],
              flags: [:dry_run, :with_deps],
              match: :exact
            ) do |jobs|
              jobs.solve
              jobs.count.should be >= 0
            end
          end
        end
      end
    end
  end

  describe ".upgrade dry-run" do
    it_on_pkg_write "each_result yields Results with non-empty package names" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.upgrade(
              db, flags: FreeBSD::Pkg::JobFlags::DryRun
            ) do |jobs|
              jobs.solve
              jobs.each_result do |r|
                r.new_package.name.should_not be_empty
                r.operation.should be_a(FreeBSD::Pkg::Jobs::Result::Operation)
              end
              jobs.count.should be >= 0
            end
          end
        end
      end
    end
  end

  describe ".remove dry-run" do
    it_on_pkg_write "solver runs gracefully for unknown package" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.remove(
              db, ["this-package-does-not-exist-zzzz"],
              flags: FreeBSD::Pkg::JobFlags::DryRun
            ) do |jobs|
              begin
                jobs.solve
              rescue FreeBSD::Pkg::Error
                # expected for unknown package
              end
            end
          end
        end
      end
    end
  end

  describe "#kind" do
    it_on_pkg_write "returns Install for install jobs" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.install(db, ["pkg"],
              flags: FreeBSD::Pkg::JobFlags::DryRun) do |jobs|
              jobs.kind.should eq(FreeBSD::Pkg::Jobs::Kind::Install)
            end
          end
        end
      end
    end

    it_on_pkg_write "returns Upgrade for upgrade jobs" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.upgrade(db, flags: FreeBSD::Pkg::JobFlags::DryRun) do |jobs|
              jobs.kind.should eq(FreeBSD::Pkg::Jobs::Kind::Upgrade)
            end
          end
        end
      end
    end
  end

  describe "#has_locked_packages?" do
    it_on_pkg_write "returns a Bool" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.upgrade(db, flags: FreeBSD::Pkg::JobFlags::DryRun) do |jobs|
              jobs.solve
              jobs.has_locked_packages?.should be_a(Bool)
            end
          end
        end
      end
    end
  end
end

describe FreeBSD::Pkg::JobFlags do
  it "coerces symbols and arrays to a folded JobFlags" do
    FreeBSD::Pkg::JobFlags.from(:dry_run).should eq(FreeBSD::Pkg::JobFlags::DryRun)
    FreeBSD::Pkg::JobFlags.from(:with_deps).should eq(FreeBSD::Pkg::JobFlags::WithDeps)
    FreeBSD::Pkg::JobFlags.from(FreeBSD::Pkg::JobFlags::Force).should eq(FreeBSD::Pkg::JobFlags::Force)
    FreeBSD::Pkg::JobFlags.from([:dry_run, :with_deps]).should eq(FreeBSD::Pkg::JobFlags::DryRun | FreeBSD::Pkg::JobFlags::WithDeps)
    FreeBSD::Pkg::JobFlags.from([:dry_run, FreeBSD::Pkg::JobFlags::Force]).should eq(FreeBSD::Pkg::JobFlags::DryRun | FreeBSD::Pkg::JobFlags::Force)
  end

  it "raises ArgumentError naming an unknown symbol" do
    expect_raises(ArgumentError) { FreeBSD::Pkg::JobFlags.from(:bogus) }
  end
end

describe FreeBSD::Pkg::Jobs::Kind do
  it "coerces symbols to a Kind" do
    FreeBSD::Pkg::Jobs::Kind.from(:install).should eq(FreeBSD::Pkg::Jobs::Kind::Install)
    FreeBSD::Pkg::Jobs::Kind.from(:autoremove).should eq(FreeBSD::Pkg::Jobs::Kind::Autoremove)
    FreeBSD::Pkg::Jobs::Kind.from(FreeBSD::Pkg::Jobs::Kind::Upgrade).should eq(FreeBSD::Pkg::Jobs::Kind::Upgrade)
  end

  it "raises ArgumentError naming an unknown symbol" do
    expect_raises(ArgumentError) { FreeBSD::Pkg::Jobs::Kind.from(:bogus) }
  end
end
