module FreeBSD::Pkg
  # A job queue for package operations: install, remove, fetch, upgrade, autoremove.
  #
  # Requires an active `FreeBSD::Pkg.init` session and a `Database` opened with
  # at least an advisory lock (use `Database#with_advisory_lock`).
  #
  # The primary API is via the block-taking class methods which manage the full
  # lifecycle automatically:
  #
  # ```
  # FreeBSD::Pkg.init do
  #   FreeBSD::Pkg::Database.open(FreeBSD::Pkg::Database::Type::MaybeRemote) do |db|
  #     db.with_advisory_lock do
  #       FreeBSD::Pkg::Jobs.install(db, ["wget"]) do |jobs|
  #         jobs.each_result { |r| puts "Will install: #{r.new_package.name}" }
  #         jobs.apply
  #       end
  #     end
  #   end
  # end
  # ```
  class Jobs
    include PkgHelpers

    # What kind of operation this job queue performs.
    enum Kind : Int32
      # Install packages from repositories (`PKG_JOBS_INSTALL`).
      Install = 0
      # Remove installed packages (`PKG_JOBS_DEINSTALL`).
      Remove = 1
      # Fetch package archives to the local cache without installing (`PKG_JOBS_FETCH`).
      Fetch = 2
      # Remove automatically-installed packages that are no longer needed (`PKG_JOBS_AUTOREMOVE`).
      Autoremove = 3
      # Upgrade all installed packages to the latest available version (`PKG_JOBS_UPGRADE`).
      Upgrade = 4
    end

    # One planned change produced by the solver.
    # Yielded by `Jobs#each_result` after `#solve` completes.
    struct Result
      # The concrete action the solver will take for one package.
      enum Operation : Int32
        # Install a new package (`PKG_SOLVED_INSTALL`).
        Install = 0
        # Remove an installed package (`PKG_SOLVED_DELETE`).
        Delete = 1
        # Upgrade an installed package to a newer version (`PKG_SOLVED_UPGRADE`).
        Upgrade = 2
        # Remove the old version as part of an upgrade (`PKG_SOLVED_UPGRADE_REMOVE`).
        UpgradeRemove = 3
        # Fetch a package archive without installing (`PKG_SOLVED_FETCH`).
        Fetch = 4
        # Install the new version as part of an upgrade (`PKG_SOLVED_UPGRADE_INSTALL`).
        UpgradeInstall = 5
      end

      # Package being installed, fetched, or upgraded to.
      getter new_package : Package
      # Previous version being replaced; `nil` for installs and fetches.
      getter old_package : Package?
      # The concrete action the solver will take.
      getter operation : Operation

      def initialize(@new_package : Package, @old_package : Package?, @operation : Operation)
      end
    end

    # -------------------------------------------------------------------
    # Class-level convenience constructors
    # -------------------------------------------------------------------

    # Opens a raw `Jobs` queue of *kind*, yields it, then frees it.
    def self.open(kind : Kind, db : Database, &) : Nil
      {% if flag?(:freebsd) %}
        jobs_ptr = Pointer(Void).null.as(LibPkg::PkgJobs)
        rc = LibPkg.pkg_jobs_new(pointerof(jobs_ptr),
          LibPkg::PkgJobsT.new(kind.value),
          db.to_unsafe)
        check_rc!(rc, "pkg_jobs_new")
        jobs = Jobs.new(jobs_ptr)
        begin
          yield jobs
        ensure
          jobs.free
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Installs *names* from repositories. Yields a `Jobs` after calling
    # `#add` and `#flags=`; caller must call `#solve` and optionally `#apply`.
    def self.install(db : Database,
                     names : Array(String),
                     flags : JobFlags | Symbol | Array = JobFlags::WithDeps,
                     match : MatchType | Symbol = MatchType::Glob,
                     &) : Nil
      open(Kind::Install, db) do |jobs|
        jobs.flags = to_job_flags(flags)
        jobs.add(names, to_match_type(match))
        yield jobs
      end
    end

    # Removes *names* from the local database.
    def self.remove(db : Database,
                    names : Array(String),
                    flags : JobFlags | Symbol | Array = JobFlags::None,
                    match : MatchType | Symbol = MatchType::Glob,
                    &) : Nil
      open(Kind::Remove, db) do |jobs|
        jobs.flags = to_job_flags(flags)
        jobs.add(names, to_match_type(match))
        yield jobs
      end
    end

    # Fetches *names* into the package cache without installing.
    def self.fetch(db : Database,
                   names : Array(String),
                   flags : JobFlags | Symbol | Array = JobFlags::None,
                   match : MatchType | Symbol = MatchType::Glob,
                   &) : Nil
      open(Kind::Fetch, db) do |jobs|
        jobs.flags = to_job_flags(flags)
        jobs.add(names, to_match_type(match))
        yield jobs
      end
    end

    # Upgrades all installed packages.
    def self.upgrade(db : Database,
                     flags : JobFlags | Symbol | Array = JobFlags::WithDeps,
                     &) : Nil
      open(Kind::Upgrade, db) do |jobs|
        jobs.flags = to_job_flags(flags)
        yield jobs
      end
    end

    # Removes packages that were installed automatically and are no longer needed.
    def self.autoremove(db : Database,
                        flags : JobFlags | Symbol | Array = JobFlags::None,
                        &) : Nil
      open(Kind::Autoremove, db) do |jobs|
        jobs.flags = to_job_flags(flags)
        yield jobs
      end
    end

    # -------------------------------------------------------------------
    # Instance API
    # -------------------------------------------------------------------

    def initialize(@handle : LibPkg::PkgJobs)
      @freed = false
      @solved = false
    end

    # Adds *names* to the job queue with the given match type.
    def add(names : Array(String),
            match : MatchType | Symbol = MatchType::Glob) : Nil
      {% if flag?(:freebsd) %}
        argv = names.map(&.to_unsafe)
        rc = LibPkg.pkg_jobs_add(@handle,
          LibPkg::MatchT.new(to_match_type(match).value),
          argv.to_unsafe,
          names.size)
        check_rc!(rc, "pkg_jobs_add")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Sets job flags (replaces any previously set flags).
    def flags=(f : JobFlags | Symbol | Array) : Nil
      {% if flag?(:freebsd) %}
        LibPkg.pkg_jobs_set_flags(@handle, to_job_flags(f).value)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Restricts repository operations to the named repository.
    def repository=(name : String) : Nil
      {% if flag?(:freebsd) %}
        rc = LibPkg.pkg_jobs_set_repository(@handle, name)
        check_rc!(rc, "pkg_jobs_set_repository")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Sets the destination directory for fetch operations.
    def dest_dir=(path : String) : Nil
      {% if flag?(:freebsd) %}
        rc = LibPkg.pkg_jobs_set_destdir(@handle, path)
        check_rc!(rc, "pkg_jobs_set_destdir")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns the current destination directory, or `nil` if unset.
    def dest_dir : String?
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_jobs_destdir(@handle)
        cstr.null? ? nil : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Runs the dependency solver. Must be called before `#each_result` or `#apply`.
    # Raises on solver failure.
    def solve : Nil
      {% if flag?(:freebsd) %}
        rc = LibPkg.pkg_jobs_solve(@handle)
        check_rc!(rc, "pkg_jobs_solve")
        @solved = true
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Yields each `Result` planned by the solver. Calls `#solve` automatically
    # if not already solved.
    #
    # Calling `#each_result` without `#apply` is a dry-run.
    def each_result(& : Result ->) : Nil
      {% if flag?(:freebsd) %}
        solve unless @solved
        iter = Pointer(Void).null
        n_ptr = Pointer(Void).null.as(LibPkg::PkgHandle)
        o_ptr = Pointer(Void).null.as(LibPkg::PkgHandle)
        op = 0_i32
        while LibPkg.pkg_jobs_iter(@handle, pointerof(iter), pointerof(n_ptr), pointerof(o_ptr), pointerof(op))
          new_pkg = Package.new(n_ptr, owns: false)
          old_pkg = o_ptr.null? ? nil : Package.new(o_ptr, owns: false)
          operation = Result::Operation.new(op)
          yield Result.new(new_pkg, old_pkg, operation)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Number of packages queued in the solved result set.
    def count : Int32
      {% if flag?(:freebsd) %}
        LibPkg.pkg_jobs_count(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Number of packages considered by the solver universe.
    def total : Int32
      {% if flag?(:freebsd) %}
        LibPkg.pkg_jobs_total(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns true if any locked package would be affected by this job.
    def has_locked_packages? : Bool
      {% if flag?(:freebsd) %}
        LibPkg.pkg_jobs_has_lockedpkgs(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Applies the solved job queue (fetch + install/remove as needed).
    # Requires `#solve` to have been called first.
    def apply : Nil
      {% if flag?(:freebsd) %}
        raise SystemError.new("pkg_jobs_apply: solve must be called before apply") unless @solved
        rc = LibPkg.pkg_jobs_apply(@handle)
        check_rc!(rc, "pkg_jobs_apply")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # The kind of operation this queue performs.
    def kind : Kind
      {% if flag?(:freebsd) %}
        Kind.new(LibPkg.pkg_jobs_type(@handle).value)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns the underlying `pkg_jobs*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgJobs
      @handle
    end

    # Frees the jobs handle. Called automatically when opened with a block.
    def free : Nil
      {% if flag?(:freebsd) %}
        return if @freed
        LibPkg.pkg_jobs_free(@handle)
        @freed = true
      {% end %}
    end

    def finalize
      free
    end
  end
end
