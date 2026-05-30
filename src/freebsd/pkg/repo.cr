module FreeBSD::Pkg
  # A configured package repository.
  #
  # Repo objects are lightweight handles backed by libpkg's internal state.
  # They are valid for the lifetime of the current `FreeBSD::Pkg.init` session.
  class Repo
    def initialize(@handle : LibPkg::PkgRepo)
    end

    # The repository name as defined in the pkg repo configuration (e.g. `"FreeBSD"`).
    def name : String
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_repo_name(@handle)
        cstr.null? ? "" : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # The fetch URL for this repository (e.g. `"pkg+https://pkg.FreeBSD.org/…"`).
    def url : String
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_repo_url(@handle)
        cstr.null? ? "" : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns `true` if this repository is enabled in the configuration.
    def enabled? : Bool
      {% if flag?(:freebsd) %}
        LibPkg.pkg_repo_enabled(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Repository priority used for conflict resolution; higher values win.
    def priority : Int32
      {% if flag?(:freebsd) %}
        LibPkg.pkg_repo_priority(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Path to the signing key for this repository, or `nil` if not configured.
    def key : String?
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_repo_key(@handle)
        cstr.null? ? nil : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns the underlying `pkg_repo*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgRepo
      @handle
    end

    # Returns all configured repositories (requires `FreeBSD::Pkg.init` to
    # have been called so that repo config is loaded).
    def self.all : Array(Repo)
      {% if flag?(:freebsd) %}
        repos = [] of Repo
        handle = Pointer(Void).null.as(LibPkg::PkgRepo)
        while LibPkg.pkg_repos(pointerof(handle)) == LibPkg::PkgErrorT::Ok.value
          repos << Repo.new(handle)
        end
        repos
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Find a repository by name. Returns `nil` if not found.
    def self.find(name : String) : Repo?
      {% if flag?(:freebsd) %}
        handle = LibPkg.pkg_repo_find(name)
        handle.null? ? nil : Repo.new(handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Total number of configured repositories (enabled and disabled).
    def self.total_count : Int32
      {% if flag?(:freebsd) %}
        LibPkg.pkg_repos_total_count
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Number of currently enabled/activated repositories.
    def self.activated_count : Int32
      {% if flag?(:freebsd) %}
        LibPkg.pkg_repos_activated_count
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end
  end
end
