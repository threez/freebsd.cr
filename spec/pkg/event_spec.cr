require "../spec_helper"

describe FreeBSD::Pkg::EventCallbacks do
  describe ".register" do
    it_on_pkg_write "callback receives events during a jobs solve+apply dry-run" do
      FreeBSD::Pkg.init do
        received = [] of FreeBSD::Pkg::Event::Kind
        FreeBSD::Pkg::EventCallbacks.register do |ev|
          received << ev.kind
        end
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.upgrade(db, flags: FreeBSD::Pkg::JobFlags::DryRun) do |jobs|
              jobs.solve
              jobs.apply
            end
          end
        end
        received.should_not be_empty
      end
    end
  end
end

describe FreeBSD::Pkg::Event do
  describe "#kind" do
    it_on_pkg_write "is a valid Kind during callback" do
      FreeBSD::Pkg.init do
        kinds = [] of FreeBSD::Pkg::Event::Kind
        FreeBSD::Pkg::EventCallbacks.register do |ev|
          kinds << ev.kind
        end
        FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
          db.with_advisory_lock do
            FreeBSD::Pkg::Jobs.upgrade(db, flags: FreeBSD::Pkg::JobFlags::DryRun) do |jobs|
              jobs.solve
              jobs.apply
            end
          end
        end
        kinds.each do |k|
          k.should be_a(FreeBSD::Pkg::Event::Kind)
        end
      end
    end
  end
end
