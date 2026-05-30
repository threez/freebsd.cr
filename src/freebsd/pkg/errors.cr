module FreeBSD::Pkg
  # Base class for all FreeBSD::Pkg errors.
  class Error < Exception
    getter errno : Errno?

    def initialize(message : String, @errno : Errno? = nil)
      super(message)
    end

    # Inspect the current `Errno` and return the most specific subclass.
    def self.from_errno(fn : String) : Error
      err = Errno.value
      case err
      when Errno::EPERM, Errno::EACCES then PermissionError.new("#{fn}: #{err}", err)
      when Errno::ENOENT               then NotFoundError.new("#{fn}: #{err}", err)
      else                                  SystemError.new("#{fn}: #{err}", err)
      end
    end

    # Map an EPKG_* return code to the most specific subclass.
    # Do NOT pass EPKG_OK (0) or EPKG_END (1) — those are not errors.
    def self.from_pkg(code : Int32, fn : String) : Error
      case code
      when 8 # EPKG_ENODB
        DatabaseError.new("#{fn}: no package database (EPKG_ENODB)")
      when 3 # EPKG_FATAL
        DatabaseError.new("#{fn}: fatal libpkg error (EPKG_FATAL)")
      when 12 # EPKG_ENOACCESS
        PermissionError.new("#{fn}: access denied (EPKG_ENOACCESS)")
      when 7 # EPKG_LOCKED
        PermissionError.new("#{fn}: database locked (EPKG_LOCKED)")
      when 14 # EPKG_CONFLICT
        ConflictError.new("#{fn}: conflict (EPKG_CONFLICT)")
      when 4 # EPKG_REQUIRED
        RequiredError.new("#{fn}: package is required by another (EPKG_REQUIRED)")
      when 5 # EPKG_INSTALLED
        SystemError.new("#{fn}: package already installed (EPKG_INSTALLED)")
      when 6 # EPKG_DEPENDENCY
        DependencyError.new("#{fn}: dependency error (EPKG_DEPENDENCY)")
      when 17 # EPKG_VITAL
        VitalError.new("#{fn}: package is vital (EPKG_VITAL)")
      else
        SystemError.new("#{fn}: libpkg error code #{code}")
      end
    end
  end

  # Raised when any FreeBSD::Pkg API is called on a platform without libpkg.
  class UnsupportedPlatformError < Error
    def initialize
      super("FreeBSD::Pkg requires FreeBSD")
    end
  end

  # Raised when the package database cannot be opened or accessed.
  class DatabaseError < Error
  end

  # Raised for EPKG_ENOACCESS or EPKG_LOCKED.
  class PermissionError < Error
  end

  # Raised for EPKG_ENOENT or ENOENT on the package database path.
  class NotFoundError < Error
  end

  # Raised for EPKG_CONFLICT.
  class ConflictError < Error
  end

  # Raised for any other libpkg or system error.
  class SystemError < Error
  end

  # Raised when a package cannot be removed because another package depends on it.
  class RequiredError < Error
  end

  # Raised for EPKG_DEPENDENCY — a dependency constraint was violated.
  class DependencyError < Error
  end

  # Raised for EPKG_VITAL — the package is marked vital and cannot be removed
  # without --force.
  class VitalError < Error
  end
end
