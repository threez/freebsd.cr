# Querying repository catalogs with FreeBSD::Pkg.
#
# Demonstrates:
#   - Listing all configured repositories
#   - Database#repo_query scoped to a specific repository
#   - Comparing a package's repo version against the installed version
#
# Run as any user (read-only, no root required):
#
#   crystal run examples/pkg/repo_query.cr

require "../../src/freebsd/pkg"

PATTERN = ARGV.first? || "pkg*"

FreeBSD::Pkg.init do
  repos = FreeBSD::Pkg::Repo.all.select(&.enabled?)
  if repos.empty?
    puts "No enabled repositories configured."
    exit
  end

  FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
    repos.each do |repo|
      puts "=== #{repo.name} (#{repo.url}) ==="

      results = db.repo_query(PATTERN,
        match: :glob,
        repo: repo.name)

      if results.empty?
        puts "  No packages matching '#{PATTERN}'"
        next
      end

      results.first(15).each do |pkg|
        # Check if this version is already installed
        installed = db.query(pkg.name, match: :exact).first?
        status = if installed
                   installed.version == pkg.version ? "up-to-date" : "upgrade: #{installed.version} → #{pkg.version}"
                 else
                   "not installed"
                 end
        size_kb = pkg.archive_size > 0 ? " #{pkg.archive_size // 1024} kB" : ""
        puts "  #{pkg.name}-#{pkg.version}#{size_kb}  [#{status}]"
      end
      puts "  ... and #{results.size - 15} more" if results.size > 15
      puts
    end
  end
end
