module FreeBSD::Privdrop
  # Base class for all privilege-drop failures.
  class Error < Exception
    getter errno : Errno?

    def initialize(message : String, @errno : Errno? = nil)
      super(message)
    end

    # Inspect the current `Errno` and return the most-specific subclass.
    # Call this immediately after a failing libc function returns -1.
    def self.from_errno(syscall : String) : Error
      err = Errno.value
      case err
      when Errno::EPERM, Errno::EACCES then PermissionError.new("#{syscall}: #{err}", err)
      when Errno::EINVAL               then InvalidArgumentError.new("#{syscall}: #{err}", err)
      else                                  SystemError.new("#{syscall}: #{err}", err)
      end
    end
  end

  # Raised when the process lacks sufficient privilege (EPERM or EACCES).
  class PermissionError < Error; end

  # Raised when an argument is out of range, e.g. ngroups > NGROUPS_MAX (EINVAL).
  class InvalidArgumentError < Error; end

  # Raised when a syscall fails for any other errno reason.
  class SystemError < Error; end

  # Raised when `freebsd/privdrop` is required on an unsupported platform.
  class UnsupportedPlatformError < Error
    def initialize
      super("FreeBSD::Privdrop requires FreeBSD or DragonFlyBSD")
    end
  end
end
