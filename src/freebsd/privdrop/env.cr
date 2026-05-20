module FreeBSD::Privdrop
  # Utilities for scrubbing dangerous environment variables before or after
  # a privilege drop. Uses Crystal's `ENV` — no FFI, no platform dependency.
  module Env
    # Variables that are silently removed if present.
    DANGEROUS_VARS = %w[
      LD_PRELOAD
      LD_LIBRARY_PATH
      LD_LIBMAP
      LD_DEBUG
      LD_ELF_HINTS_PATH
      DYLD_INSERT_LIBRARIES
      DYLD_LIBRARY_PATH
      IFS
      CDPATH
      ENV
      BASH_ENV
    ]

    # PATH is reset to this safe value rather than removed entirely.
    SAFE_PATH = "/usr/bin:/bin"

    # Remove all known-dangerous variables and reset PATH to `SAFE_PATH`.
    # Returns the names of variables that were actually present and removed.
    def self.scrub : Array(String)
      removed = [] of String
      DANGEROUS_VARS.each do |name|
        removed << name if ENV.delete(name)
      end
      ENV["PATH"] = SAFE_PATH
      removed
    end

    # Remove a single environment variable by name. Returns true if it existed.
    def self.delete(name : String) : Bool
      !ENV.delete(name).nil?
    end

    # Reset PATH to `SAFE_PATH`. Returns the previous value (or nil if unset).
    def self.reset_path : String?
      old = ENV["PATH"]?
      ENV["PATH"] = SAFE_PATH
      old
    end
  end
end
