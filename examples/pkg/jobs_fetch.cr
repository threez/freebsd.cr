# Fetching packages to the local cache with FreeBSD::Pkg.
#
# Downloads package archives without installing them. Useful for
# staging upgrades or air-gapped environments.
#
# Demonstrates:
#   - Jobs.fetch with event callbacks for progress reporting
#   - jobs.each_result to inspect what will be fetched before applying
#   - jobs.apply to actually perform the download (requires root)
#   - Dry-run mode (solve without apply) works as any user
#
# Run as any user for dry-run, root to actually fetch:
#
#   crystal run examples/pkg/jobs_fetch.cr -- units
#   crystal run examples/pkg/jobs_fetch.cr -- --apply units

require "../../src/freebsd/pkg"

apply = ARGV.first? == "--apply"
names = apply ? ARGV[1..].to_a : ARGV.to_a
names = ["units"] if names.empty?

FreeBSD::Pkg.init do
  FreeBSD::Pkg::EventCallbacks.register do |ev|
    case ev.kind
    when .fetch_begin?
      print "  fetching #{ev.url}... "
      STDOUT.flush
    when .fetch_finished?
      puts "done"
    when .progress_tick?
      cur = ev.progress_current || 0_i64
      tot = ev.progress_total || 0_i64
      print "\r  #{cur * 100 // (tot > 0 ? tot : 1)}%"
      STDOUT.flush
    else
      # ignore
    end
  end

  FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
    FreeBSD::Pkg::Jobs.fetch(db, names, flags: :none) do |jobs|
      jobs.solve

      count = jobs.count
      if count == 0
        puts "Nothing to fetch (all packages already cached or installed)."
        next
      end

      puts "Packages to fetch (#{count}):"
      total_bytes = 0_i64
      jobs.each_result do |r|
        size = r.new_package.archive_size
        total_bytes += size
        size_str = size > 0 ? " (#{size // 1024} kB)" : ""
        puts "  #{r.new_package.name}-#{r.new_package.version}#{size_str}"
      end
      puts "Total download: #{total_bytes // 1024} kB" if total_bytes > 0
      puts

      if apply
        # Fetch writes to /var/cache/pkg — requires advisory lock (root).
        db.with_advisory_lock do
          puts "Fetching..."
          jobs.apply
          puts "\nDone."
        end
      else
        puts "(dry run — pass --apply to download)"
      end
    end
  end
end
