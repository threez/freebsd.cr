module FreeBSD::Capsicum
  # FreeBSD's Capsicum-specific errnos. Not enumerated in Crystal's `Errno`
  # stdlib so we compare against the raw constants.
  ECAPMODE    = 94
  ENOTCAPABLE = 93

  # Base class for all FreeBSD::Capsicum errors. Carries the `errno` at the point of failure.
  class Error < Exception
    getter errno : Errno?

    def initialize(message : String, @errno : Errno? = nil)
      super(message)
    end

    # Inspect the current `Errno` and return the most specific subclass.
    def self.from_errno(message : String) : Error
      err = Errno.value
      case err.value
      when ECAPMODE    then NotCapableError.new(message, err)
      when ENOTCAPABLE then InsufficientRightsError.new(message, err)
      else
        case err
        when Errno::EPERM, Errno::EACCES then PermissionError.new(message, err)
        else                                  SystemError.new("#{message}: #{err}", err)
        end
      end
    end
  end

  # Raised when any FreeBSD::Capsicum or FreeBSD::Casper API is called on a platform without Capsicum/libcasper.
  class UnsupportedPlatformError < Error
    def initialize
      super("Capsicum/libcasper is only available on FreeBSD (and partially DragonFlyBSD); current target lacks support")
    end
  end

  # Raised when a syscall is blocked because the process is in capability mode (`ECAPMODE`).
  class NotCapableError < Error
  end

  # Raised when an fd's rights do not permit the requested operation (`ENOTCAPABLE`).
  class InsufficientRightsError < Error
  end

  # Raised for `EPERM` / `EACCES` failures on Capsicum operations.
  class PermissionError < Error
  end

  # Raised for any other errno from a Capsicum or Casper syscall.
  class SystemError < Error
  end
end
