# Full-text search across configured repositories with FreeBSD::Pkg.
#
# Demonstrates:
#   - Database#search with SearchField options (name, comment, description)
#   - Sorting results by name
#   - Showing download size, origin, and comment per result
#
# Run as any user (read-only, no root required):
#
#   crystal run examples/pkg/search.cr

require "../../src/freebsd/pkg"

QUERY = ARGV.first? || "http"

FreeBSD::Pkg.init do
  FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
    # -------------------------------------------------------------------
    # 1. Search by name — packages whose name contains the query
    # -------------------------------------------------------------------
    puts "=== Packages matching '#{QUERY}' by name ==="
    results = db.search(QUERY,
      field: FreeBSD::Pkg::SearchField::Name,
      sort: FreeBSD::Pkg::SearchField::Name)
    if results.empty?
      puts "  (none)"
    else
      results.first(10).each do |pkg|
        size_kb = pkg.archive_size > 0 ? " [#{pkg.archive_size // 1024} kB]" : ""
        puts "  #{pkg.name}-#{pkg.version}#{size_kb}"
        puts "    #{pkg.comment}" unless pkg.comment.empty?
      end
      puts "  ... and #{results.size - 10} more" if results.size > 10
    end
    puts

    # -------------------------------------------------------------------
    # 2. Search by comment — packages whose one-liner matches
    # -------------------------------------------------------------------
    puts "=== Packages matching '#{QUERY}' in comment ==="
    by_comment = db.search(QUERY,
      field: FreeBSD::Pkg::SearchField::Comment,
      sort: FreeBSD::Pkg::SearchField::Name)
    if by_comment.empty?
      puts "  (none)"
    else
      by_comment.first(10).each do |pkg|
        puts "  #{pkg.name}-#{pkg.version} (#{pkg.origin})"
        puts "    #{pkg.comment}" unless pkg.comment.empty?
      end
      puts "  ... and #{by_comment.size - 10} more" if by_comment.size > 10
    end
    puts

    # -------------------------------------------------------------------
    # 3. Search by name+version (NameVer) — useful for version pinning
    # -------------------------------------------------------------------
    puts "=== Packages matching '#{QUERY}' by name+version ==="
    by_namever = db.search(QUERY,
      field: FreeBSD::Pkg::SearchField::NameVer,
      sort: FreeBSD::Pkg::SearchField::Name)
    puts "  #{by_namever.size} result(s)"
  end
end
