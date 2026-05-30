require "../spec_helper"

describe FreeBSD::Pkg::Repo do
  describe ".total_count" do
    it_on_pkg "returns a non-negative integer" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Repo.total_count.should be >= 0
      end
    end
  end

  describe ".activated_count" do
    it_on_pkg "returns a non-negative integer" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Repo.activated_count.should be >= 0
      end
    end

    it_on_pkg "activated count <= total count" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Repo.activated_count.should be <= FreeBSD::Pkg::Repo.total_count
      end
    end
  end

  describe ".all" do
    it_on_pkg "returns an Array(Repo)" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Repo.all.should be_a(Array(FreeBSD::Pkg::Repo))
      end
    end

    it_on_pkg "each repo has a non-empty name" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Repo.all.each do |repo|
          repo.name.should_not be_empty
        end
      end
    end

    it_on_pkg "each repo has a non-empty url" do
      FreeBSD::Pkg.init do
        FreeBSD::Pkg::Repo.all.each do |repo|
          repo.url.should_not be_empty
        end
      end
    end
  end

  describe ".find" do
    it_on_pkg "returns nil for an unknown repo name" do
      FreeBSD::Pkg.init do
        result = FreeBSD::Pkg::Repo.find("this-repo-does-not-exist-zzzz")
        result.should be_nil
      end
    end

    it_on_pkg "round-trips: find the first repo by name" do
      FreeBSD::Pkg.init do
        repos = FreeBSD::Pkg::Repo.all
        next if repos.empty?
        first = repos.first
        found = FreeBSD::Pkg::Repo.find(first.name)
        found.should_not be_nil
        found.not_nil!.name.should eq(first.name)
      end
    end
  end
end
