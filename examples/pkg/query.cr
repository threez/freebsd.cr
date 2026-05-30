# Querying the local package database with FreeBSD::Pkg.
#
# Demonstrates:
#   - Listing all installed packages
#   - Querying a specific package by name with metadata
#   - Iterating dependencies
#   - Listing configured repositories
#
# Run as any user (read-only, no root required):
#
#   crystal run examples/pkg/query.cr

require "../../src/freebsd/pkg"

FreeBSD::Pkg.init do
  FreeBSD::Pkg::Database.open do |db|
    # -------------------------------------------------------------------
    # 1. Count installed packages
    # -------------------------------------------------------------------
    count = 0
    db.each { count += 1 }
    puts "Installed packages: #{count}"
    puts

    # -------------------------------------------------------------------
    # 2. Look up 'pkg' itself — name, version, size, origin
    # -------------------------------------------------------------------
    pkgs = db.query("pkg", match: :exact, flags: [:deps, :annotations])

    if pkg = pkgs.first?
      puts "#{pkg.name}-#{pkg.version}"
      puts "  origin:  #{pkg.origin}"
      puts "  prefix:  #{pkg.prefix}"
      puts "  abi:     #{pkg.abi}"
      puts "  size:    #{pkg.installed_size} bytes"
      puts "  auto:    #{pkg.automatic?}"
      puts "  locked:  #{pkg.locked?}"
      puts "  vital:   #{pkg.vital?}"
      puts "  type:    #{pkg.type}"
      puts

      # Annotations
      ann = pkg.annotations
      unless ann.empty?
        puts "  annotations:"
        ann.each { |k, v| puts "    #{k} = #{v}" }
        puts
      end

      # Dependencies
      deps = [] of String
      pkg.each_dependency { |dep| deps << "#{dep.name}-#{dep.version}" }
      unless deps.empty?
        puts "  dependencies (#{deps.size}):"
        deps.first(5).each { |d| puts "    #{d}" }
        puts "    ..." if deps.size > 5
        puts
      end
    else
      puts "pkg not found in local database"
    end

    # -------------------------------------------------------------------
    # 3. Which package owns /usr/local/sbin/pkg?
    # -------------------------------------------------------------------
    if owner = db.which("/usr/local/sbin/pkg")
      puts "/usr/local/sbin/pkg is owned by: #{owner.name}-#{owner.version}"
    end
    puts

    # -------------------------------------------------------------------
    # 4. Packages requiring libpkg (version determined from pkg's provided shlibs)
    # -------------------------------------------------------------------
    libpkg = db.query("pkg", match: :exact, flags: :shlibs_provided)
      .first?
      .try { |p| p.shlibs_provided.find(&.starts_with?("libpkg.so")) }

    if libpkg
      libpkg_users = db.requiring_shlib(libpkg)
      puts "Packages requiring #{libpkg}: #{libpkg_users.size}"
      libpkg_users.first(3).each { |p| puts "  #{p.name}-#{p.version}" }
      puts "  ..." if libpkg_users.size > 3
    else
      puts "pkg provides no libpkg shlib"
    end
    puts
  end

  # -------------------------------------------------------------------
  # 5. Configured repositories
  # -------------------------------------------------------------------
  repos = FreeBSD::Pkg::Repo.all
  if repos.empty?
    puts "No repositories configured."
  else
    puts "Repositories (#{repos.size}):"
    repos.each do |r|
      status = r.enabled? ? "enabled" : "disabled"
      puts "  #{r.name} [#{status}] #{r.url}"
    end
  end
end
