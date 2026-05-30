module FreeBSD::Pkg
  # A handle to the local package database (and optionally configured repositories).
  #
  # Always open with a block to ensure the lock is released and the handle is closed:
  #
  # ```
  # FreeBSD::Pkg.init do
  #   FreeBSD::Pkg::Database.open do |db|
  #     db.each { |pkg| puts pkg.name }
  #   end
  # end
  # ```
  class Database
    include PkgHelpers

    # Controls which databases are opened.
    enum Type : Int32
      # Installed packages only (`PKGDB_DEFAULT`). Sufficient for all read queries against the local database.
      Local = 0
      # Repository catalogs only (`PKGDB_REMOTE`). Use for `repo_query` or `search` when you do not need local info.
      Remote = 1
      # Local database plus remote catalogs when at least one repository is configured (`PKGDB_MAYBE_REMOTE`). Required for `Jobs` operations.
      MaybeRemote = 2
      # Local database, read-only (`PKGDB_DEFAULT_READONLY`). Skips the advisory lock; use when write access is not available.
      LocalReadonly = 3
    end

    # Re-exported for backward compatibility — defined at `FreeBSD::Pkg::MatchType`.
    MatchType = FreeBSD::Pkg::MatchType
    # Re-exported for backward compatibility — defined at `FreeBSD::Pkg::SearchField`.
    SearchField = FreeBSD::Pkg::SearchField

    @closed = false

    # Opens the database, yields it, and closes it when the block exits.
    def self.open(type : Type = Type::Local, &) : Nil
      db = open(type)
      begin
        yield db
      ensure
        db.close
      end
    end

    # Opens the database and returns the handle. The caller must call `#close`.
    def self.open(type : Type = Type::Local) : Database
      {% if flag?(:freebsd) %}
        db_ptr = Pointer(Void).null.as(LibPkg::PkgDb)
        rc = LibPkg.pkgdb_open(pointerof(db_ptr), LibPkg::PkgdbT.new(type.value))
        check_rc!(rc, "pkgdb_open")
        db = Database.new(db_ptr)
        rc = LibPkg.pkgdb_obtain_lock(db_ptr, LibPkg::PkgdbLockT::Readonly)
        unless rc == LibPkg::PkgErrorT::Ok.value
          db.close
          raise Error.from_pkg(rc, "pkgdb_obtain_lock")
        end
        db
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    protected def initialize(@handle : LibPkg::PkgDb)
    end

    # Releases the database lock and closes the handle.
    # Called automatically when using the block form of `.open`.
    # Safe to call multiple times — subsequent calls are no-ops.
    def close : Nil
      {% if flag?(:freebsd) %}
        return if @closed
        LibPkg.pkgdb_release_lock(@handle, LibPkg::PkgdbLockT::Readonly)
        LibPkg.pkgdb_close(@handle)
        @closed = true
      {% end %}
    end

    # Returns `true` if `#close` has been called.
    def closed? : Bool
      @closed
    end

    # Returns the underlying `pkgdb*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgDb
      @handle
    end

    def finalize
      close
    end

    # -------------------------------------------------------------------
    # Streaming query (efficient — no Array allocation)
    # -------------------------------------------------------------------

    # Yields each installed package matching *pattern*.
    # When *pattern* is `nil`, all installed packages are enumerated.
    #
    # The yielded `Package` is **ephemeral** — do not retain it past the block.
    # Use `#query` for an `Array(Package)` with independently-owned handles.
    def each(pattern : String? = nil,
             match : FreeBSD::Pkg::MatchType | Symbol = FreeBSD::Pkg::MatchType::All,
             flags : LoadFlags | Symbol | Array = LoadFlags::None,
             & : Package ->) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query(@handle, pattern, LibPkg::MatchT.new(to_match_type(match).value))
        raise SystemError.new("pkgdb_query returned null") if it_ptr.null?
        it = Iterator.new(it_ptr, flags)
        begin
          it.each { |pkg| yield pkg }
        ensure
          it.close
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Array-returning queries
    # -------------------------------------------------------------------

    # Returns all installed packages matching *pattern* as an `Array(Package)`.
    # Each package in the array owns its handle and is freed when GC'd.
    def query(pattern : String? = nil,
              match : FreeBSD::Pkg::MatchType | Symbol = FreeBSD::Pkg::MatchType::All,
              flags : LoadFlags | Symbol | Array = LoadFlags::None) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query(@handle, pattern, LibPkg::MatchT.new(to_match_type(match).value))
        raise SystemError.new("pkgdb_query returned null") if it_ptr.null?
        collect_iterator(it_ptr, to_load_flags(flags))
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns packages available in the named repository (or all repos if
    # *repo* is `nil`) matching *pattern*.
    def repo_query(pattern : String,
                   match : FreeBSD::Pkg::MatchType | Symbol = FreeBSD::Pkg::MatchType::Glob,
                   repo : String? = nil,
                   flags : LoadFlags | Symbol | Array = LoadFlags::None) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_repo_query(@handle, pattern,
          LibPkg::MatchT.new(to_match_type(match).value), repo)
        raise SystemError.new("pkgdb_repo_query returned null") if it_ptr.null?
        collect_iterator(it_ptr, to_load_flags(flags))
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Full-text search across local and remote databases.
    # *match* controls how *pattern* is interpreted against *field*.
    # Defaults to `MatchType::Regex` (case-insensitive substring via regex).
    def search(pattern : String,
               field : FreeBSD::Pkg::SearchField = FreeBSD::Pkg::SearchField::NameVer,
               sort : FreeBSD::Pkg::SearchField = FreeBSD::Pkg::SearchField::None,
               match : FreeBSD::Pkg::MatchType | Symbol = FreeBSD::Pkg::MatchType::Regex,
               repo : String? = nil,
               flags : LoadFlags | Symbol | Array = LoadFlags::None) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_all_search(@handle, pattern,
          LibPkg::MatchT.new(to_match_type(match).value),
          LibPkg::PkgdbField.new(field.value),
          LibPkg::PkgdbField.new(sort.value),
          repo)
        raise SystemError.new("pkgdb_all_search returned null") if it_ptr.null?
        collect_iterator(it_ptr, to_load_flags(flags))
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Reverse lookups
    # -------------------------------------------------------------------

    # Returns the installed package that owns *path*, or `nil` if not found.
    # *glob* enables shell-glob matching on the path.
    def which(path : String, glob : Bool = false) : Package?
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query_which(@handle, path, glob)
        return nil if it_ptr.null?
        pkgs = collect_iterator(it_ptr, LoadFlags::None)
        pkgs.first?
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns all installed packages that require the shared library *shlib*.
    def requiring_shlib(shlib : String) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query_shlib_require(@handle, shlib)
        return [] of Package if it_ptr.null?
        collect_iterator(it_ptr, LoadFlags::None)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns all installed packages that provide the shared library *shlib*.
    def providing_shlib(shlib : String) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query_shlib_provide(@handle, shlib)
        return [] of Package if it_ptr.null?
        collect_iterator(it_ptr, LoadFlags::None)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns all installed packages that require the abstract *req* string.
    def requiring(req : String) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query_require(@handle, req)
        return [] of Package if it_ptr.null?
        collect_iterator(it_ptr, LoadFlags::None)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns all installed packages that provide the abstract *req* string.
    def providing(req : String) : Array(Package)
      {% if flag?(:freebsd) %}
        check_open!
        it_ptr = LibPkg.pkgdb_query_provide(@handle, req)
        return [] of Package if it_ptr.null?
        collect_iterator(it_ptr, LoadFlags::None)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Write lock management
    # -------------------------------------------------------------------

    # Escalates the database lock to `ADVISORY`, yields, then downgrades back
    # to `READONLY`. Required before annotation, locking, or `pkgdb_set2`
    # operations.
    #
    # The database must have been opened with `Type::Local`, `Type::Remote`, or
    # `Type::MaybeRemote` (not `Type::LocalReadonly`).
    def with_advisory_lock(&) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkgdb_upgrade_lock(@handle,
          LibPkg::PkgdbLockT::Readonly, LibPkg::PkgdbLockT::Advisory)
        check_rc!(rc, "pkgdb_upgrade_lock")
        begin
          yield
        ensure
          LibPkg.pkgdb_downgrade_lock(@handle,
            LibPkg::PkgdbLockT::Advisory, LibPkg::PkgdbLockT::Readonly)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Escalates the database lock to `EXCLUSIVE`, yields, then downgrades back
    # to `READONLY`. Required for operations that must prevent concurrent readers.
    def with_exclusive_lock(&) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkgdb_upgrade_lock(@handle,
          LibPkg::PkgdbLockT::Readonly, LibPkg::PkgdbLockT::Exclusive)
        check_rc!(rc, "pkgdb_upgrade_lock")
        begin
          yield
        ensure
          LibPkg.pkgdb_downgrade_lock(@handle,
            LibPkg::PkgdbLockT::Exclusive, LibPkg::PkgdbLockT::Readonly)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Transactions
    # -------------------------------------------------------------------

    # Wraps the block in a database transaction (or savepoint if *savepoint*
    # is given). Commits on success, rolls back on exception.
    def transaction(savepoint : String? = nil, &) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        sp = savepoint
        rc = LibPkg.pkgdb_transaction_begin(@handle, sp)
        check_rc!(rc, "pkgdb_transaction_begin")
        begin
          yield
          rc = LibPkg.pkgdb_transaction_commit(@handle, sp)
          check_rc!(rc, "pkgdb_transaction_commit")
        rescue ex
          LibPkg.pkgdb_transaction_rollback(@handle, sp)
          raise ex
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Annotation CRUD (require advisory lock)
    # -------------------------------------------------------------------

    # Adds an annotation *tag* = *value* to *pkg* in the database.
    def add_annotation(pkg : Package, tag : String, value : String) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkgdb_add_annotation(@handle, pkg.to_unsafe, tag, value)
        check_rc!(rc, "pkgdb_add_annotation")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Updates an existing annotation *tag* on *pkg* to *value*.
    def modify_annotation(pkg : Package, tag : String, value : String) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkgdb_modify_annotation(@handle, pkg.to_unsafe, tag, value)
        check_rc!(rc, "pkgdb_modify_annotation")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Removes annotation *tag* from *pkg* in the database.
    def delete_annotation(pkg : Package, tag : String) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkgdb_delete_annotation(@handle, pkg.to_unsafe, tag)
        check_rc!(rc, "pkgdb_delete_annotation")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Package attribute flags (require advisory lock)
    # -------------------------------------------------------------------

    # Marks *pkg* as locked in the database (protected from removal/upgrade).
    def lock(pkg : Package) : Nil
      set_pkg_attr(pkg, LibPkg::PkgSetAttr::Locked, 1_i64)
    end

    # Removes the lock flag from *pkg* in the database.
    def unlock(pkg : Package) : Nil
      set_pkg_attr(pkg, LibPkg::PkgSetAttr::Locked, 0_i64)
    end

    # Sets the vital flag on *pkg* (prevents removal without `--force`).
    def set_vital(pkg : Package, vital : Bool) : Nil
      set_pkg_attr(pkg, LibPkg::PkgSetAttr::Vital, vital ? 1_i64 : 0_i64)
    end

    # Sets the automatic flag on *pkg* (marks it as an auto-installed dependency).
    def set_automatic(pkg : Package, automatic : Bool) : Nil
      set_pkg_attr(pkg, LibPkg::PkgSetAttr::Automatic, automatic ? 1_i64 : 0_i64)
    end

    # -------------------------------------------------------------------
    # Repository catalog update
    # -------------------------------------------------------------------

    # Refreshes the catalog for *repo* from its configured URL.
    # Pass `force: true` to fetch even when the catalog appears up-to-date.
    def update_repo(repo : Repo, force : Bool = false) : Nil
      {% if flag?(:freebsd) %}
        rc = LibPkg.pkg_update(repo.to_unsafe, force)
        check_rc_or_uptodate!(rc, "pkg_update")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Direct local archive install
    # -------------------------------------------------------------------

    # Installs a local `.pkg` archive directly, bypassing the solver.
    # *location* can restrict the install root (pass `nil` for the system default).
    def add(path : String, flags : AddFlags = AddFlags::None, location : String? = nil) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkg_add(@handle, path, flags.value, location)
        check_rc!(rc, "pkg_add")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Convenience
    # -------------------------------------------------------------------

    # Returns true if the package named *name* is installed.
    def installed?(name : String) : Bool
      {% if flag?(:freebsd) %}
        check_open!
        LibPkg.pkg_is_installed(@handle, name) == LibPkg::PkgErrorT::Ok.value
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    private def check_open! : Nil
      raise DatabaseError.new("database is closed") if @closed
    end

    # Calls pkgdb_set2 to update a single integer-valued package attribute.
    # pkgdb_set2 is variadic: (db, pkg, attr, value, -1) where -1 terminates the list.
    private def set_pkg_attr(pkg : Package, attr : LibPkg::PkgSetAttr, value : Int64) : Nil
      {% if flag?(:freebsd) %}
        check_open!
        rc = LibPkg.pkgdb_set2(@handle, pkg.to_unsafe, attr.value, value, -1_i32)
        check_rc!(rc, "pkgdb_set2")
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    private def collect_iterator(it_ptr : LibPkg::PkgDbIt,
                                 flags : LoadFlags) : Array(Package)
      it = Iterator.new(it_ptr, flags)
      begin
        it.collect
      ensure
        it.close
      end
    end
  end
end
