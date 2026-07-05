# Crystal bindings for FreeBSD's libpkg package management library.
#
# Provides Crystal-idiomatic access to the local package database and
# configured repositories, including read operations (querying installed
# packages, searching repos, reading package metadata) and write operations
# (install, remove, upgrade, fetch, autoremove via the jobs API, annotation
# CRUD, package locking, repo catalog updates, and event callbacks).
#
# ## Quick start
#
# ```
# require "freebsd/pkg"
#
# FreeBSD::Pkg.init do
#   FreeBSD::Pkg::Database.open do |db|
#     db.each { |pkg| puts "#{pkg.name}-#{pkg.version}" }
#   end
# end
# ```
#
# ## Repo listing
#
# ```
# FreeBSD::Pkg.init do
#   FreeBSD::Pkg::Repo.all.each { |r| puts "#{r.name}: #{r.url}" }
# end
# ```
module FreeBSD::Pkg
  # True when running on a platform where these bindings are functional (FreeBSD).
  SUPPORTED = {{ flag?(:freebsd) }}

  # Network protocol preference flags for `init` / `init!`.
  #
  # Combine values with `|`, or pass a symbol / array of symbols:
  #
  # ```
  # FreeBSD::Pkg.init(flags: :use_ipv4) { }
  # FreeBSD::Pkg.init(flags: [:use_ipv4, :use_ipv6]) { }
  # FreeBSD::Pkg.init(flags: InitFlags::UseIpv4 | InitFlags::UseIpv6) { }
  # ```
  @[Flags]
  enum InitFlags : UInt32
    # Prefer IPv4 for repository connections.
    UseIpv4 = 1
    # Prefer IPv6 for repository connections.
    UseIpv6 = 2

    # Coerce a `Symbol`, an `InitFlags`, or an `Enumerable` of either into a
    # single `InitFlags`. Symbols name members case-insensitively with `_`
    # word separators (`:use_ipv4`, `:use_ipv6`); an array is OR-folded so
    # `[:use_ipv4, :use_ipv6]` replaces
    # `InitFlags::UseIpv4 | InitFlags::UseIpv6`. Raises `ArgumentError`
    # naming a bad symbol.
    def self.from(value : Symbol | InitFlags) : InitFlags
      case value
      in InitFlags then value
      in Symbol    then parse(value.to_s)
      end
    end

    # :ditto:
    def self.from(values : Enumerable(Symbol | InitFlags)) : InitFlags
      values.reduce(InitFlags::None) { |acc, v| acc | from(v) }
    end
  end

  # Initializes libpkg, yields, then shuts it down.
  #
  # This is the recommended entry point. All `Database` and `Repo` operations
  # must be called within an active `init` session.
  #
  # *conffile* and *repodir* may be `nil` to use the system defaults
  # (`/usr/local/etc/pkg.conf` and `/usr/local/etc/pkg/repos/`).
  def self.init(conffile : String? = nil,
                repodir : String? = nil,
                flags : InitFlags | Symbol | Enumerable(Symbol | InitFlags) = InitFlags::None, &) : Nil
    init!(conffile, repodir, flags)
    begin
      yield
    ensure
      shutdown
    end
  end

  # Initializes libpkg without a block. The caller must call `.shutdown`.
  def self.init!(conffile : String? = nil,
                 repodir : String? = nil,
                 flags : InitFlags | Symbol | Enumerable(Symbol | InitFlags) = InitFlags::None) : Nil
    {% if flag?(:freebsd) %}
      rc = LibPkg.pkg_ini(conffile, repodir, LibPkg::PkgInitFlags.new(InitFlags.from(flags).value))
      raise Error.from_pkg(rc, "pkg_ini") unless rc == LibPkg::PkgErrorT::Ok.value
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Shuts down libpkg, releasing all internal state.
  def self.shutdown : Nil
    {% if flag?(:freebsd) %}
      LibPkg.pkg_shutdown
    {% end %}
  end

  # Returns true if libpkg has been initialized.
  def self.initialized? : Bool
    {% if flag?(:freebsd) %}
      LibPkg.pkg_initialized != 0
    {% else %}
      false
    {% end %}
  end

  # Controls whether pattern matching is case-sensitive for subsequent queries.
  # The default is determined by libpkg configuration.
  def self.case_sensitive=(value : Bool) : Nil
    {% if flag?(:freebsd) %}
      LibPkg.pkgdb_set_case_sensitivity(value)
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Returns the current case-sensitivity setting for pattern matching.
  def self.case_sensitive? : Bool
    {% if flag?(:freebsd) %}
      LibPkg.pkgdb_case_sensitive
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Compares two package version strings.
  # Returns a negative integer, zero, or a positive integer if *a* is less than,
  # equal to, or greater than *b* — consistent with `Comparable#<=>`.
  def self.version_cmp(a : String, b : String) : Int32
    {% if flag?(:freebsd) %}
      LibPkg.pkg_version_cmp(a, b)
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end
end

require "./pkg/lib_pkg"
require "./pkg/errors"
require "./pkg/helpers"
require "./pkg/load_flags"
require "./pkg/job_flags"
require "./pkg/match_type"
require "./pkg/add_flags"
require "./pkg/package"
require "./pkg/dependency"
require "./pkg/file_entry"
require "./pkg/dir_entry"
require "./pkg/repo"
require "./pkg/iterator"
require "./pkg/database"
require "./pkg/event"
require "./pkg/jobs"
