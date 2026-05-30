# Dry-run package install with FreeBSD::Pkg.
#
# Resolves dependencies and prints the install plan without applying it.
# Add `--apply` as the first argument to actually install.
#
# Demonstrates:
#   - Jobs.install with dependency resolution
#   - Inspecting each Result (operation, new/old package, sizes)
#   - Event callbacks for live progress when applying
#   - jobs.has_locked_packages? safety check
#   - Dry-run (solve without lock) vs apply (requires advisory lock + root)
#
# Run as any user for dry-run, root to apply:
#
#   crystal run examples/pkg/jobs_install.cr -- units
#   crystal run examples/pkg/jobs_install.cr -- --apply units

require "../../src/freebsd/pkg"

apply = ARGV.first? == "--apply"
names = apply ? ARGV[1..].to_a : ARGV.to_a
names = ["units"] if names.empty?

FreeBSD::Pkg.init do
  FreeBSD::Pkg::EventCallbacks.register do |ev|
    case ev.kind
    when .install_begin?
      puts "  installing #{ev.package.try(&.name)}..."
    when .extract_begin?
      print "    extracting... "
      STDOUT.flush
    when .extract_finished?
      puts "done"
    when .fetch_begin?
      print "  fetching #{ev.url}... "
      STDOUT.flush
    when .fetch_finished?
      puts "done"
    when .notice?
      puts "  notice: #{ev.message}" if ev.message
    else
      # ignore
    end
  end

  FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
    FreeBSD::Pkg::Jobs.install(db, names, flags: :with_deps) do |jobs|
      jobs.solve

      count = jobs.count
      if count == 0
        puts "Nothing to do — all packages already installed."
        next
      end

      if jobs.has_locked_packages?
        puts "WARNING: some affected packages are locked."
      end

      puts "Install plan (#{count} package#{count == 1 ? "" : "s"}):"
      install_bytes = 0_i64
      download_bytes = 0_i64
      jobs.each_result do |r|
        pkg = r.new_package
        install_bytes += pkg.installed_size
        download_bytes += pkg.archive_size
        case r.operation
        when .install?
          puts "  install   #{pkg.name}-#{pkg.version} (#{pkg.installed_size // 1024} kB on disk)"
        when .upgrade?
          old = r.old_package.not_nil!
          puts "  upgrade   #{old.name}-#{old.version} → #{pkg.version} (#{pkg.installed_size // 1024} kB)"
        when .fetch?
          puts "  fetch     #{pkg.name}-#{pkg.version}"
        else
          puts "  #{r.operation.to_s.downcase.ljust(9)} #{pkg.name}-#{pkg.version}"
        end
      end
      puts
      puts "  Download : #{download_bytes // 1024} kB" if download_bytes > 0
      puts "  Disk use : #{install_bytes // 1024} kB"
      puts

      if apply
        # Applying requires an advisory lock (write access to pkg db — needs root).
        db.with_advisory_lock do
          puts "Applying..."
          jobs.apply
          puts "Done."
        end
      else
        puts "(dry run — pass --apply to install)"
      end
    end
  end
end
