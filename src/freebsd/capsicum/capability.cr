module FreeBSD::Capsicum
  # Enter capability mode for the current process and yield. Once entered the
  # process can never leave; the block (and everything after it) runs sandboxed.
  #
  # On non-FreeBSD platforms this raises `UnsupportedPlatformError` before
  # yielding.
  def self.sandbox(&) : Nil
    sandbox!
    yield
  end

  # Enter capability mode. One-way; never returns to an unsandboxed state.
  def self.sandbox! : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if LibCapsicum.cap_enter != 0
        raise Error.from_errno("cap_enter")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # True when the current process is in capability mode.
  def self.sandboxed? : Bool
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      LibCapsicum.cap_sandboxed
    {% else %}
      false
    {% end %}
  end

  module Capability
    # Capsicum right. Backing values match the CAP_* macros from
    # <sys/capsicum.h>: each right is encoded as `(1 << (57+idx)) | bit`.
    # Only the most commonly used rights are enumerated; for anything not
    # listed here, pass a raw UInt64 to `Rights#add_raw`.
    @[Flags]
    enum Right : UInt64
      # Index 0 rights
      Read      = (1_u64 << 57) | 0x0000000000000001_u64
      Write     = (1_u64 << 57) | 0x0000000000000002_u64
      SeekTell  = (1_u64 << 57) | 0x0000000000000004_u64
      Seek      = (1_u64 << 57) | 0x000000000000000c_u64
      Mmap      = (1_u64 << 57) | 0x0000000000000010_u64
      MmapX     = (1_u64 << 57) | 0x0000000000000020_u64
      Create    = (1_u64 << 57) | 0x0000000000000040_u64
      Fexecve   = (1_u64 << 57) | 0x0000000000000080_u64
      Fsync     = (1_u64 << 57) | 0x0000000000000100_u64
      Ftruncate = (1_u64 << 57) | 0x0000000000000200_u64
      Lookup    = (1_u64 << 57) | 0x0000000000000400_u64
      Fchdir    = (1_u64 << 57) | 0x0000000000000800_u64
      Fchflags  = (1_u64 << 57) | 0x0000000000001000_u64
      Fchmod    = (1_u64 << 57) | 0x0000000000002000_u64
      Fchown    = (1_u64 << 57) | 0x0000000000004000_u64
      Fcntl     = (1_u64 << 57) | 0x0000000000008000_u64
      Flock     = (1_u64 << 57) | 0x0000000000010000_u64
      Fpathconf = (1_u64 << 57) | 0x0000000000020000_u64
      Fsck      = (1_u64 << 57) | 0x0000000000040000_u64
      Fstat     = (1_u64 << 57) | 0x0000000000080000_u64
      Fstatfs   = (1_u64 << 57) | 0x0000000000100000_u64
      Futimes   = (1_u64 << 57) | 0x0000000000200000_u64
      # Socket rights (all index 0; bits per <sys/capsicum.h>).
      Accept      = (1_u64 << 57) | 0x0000000020000000_u64
      Bind        = (1_u64 << 57) | 0x0000000040000000_u64
      Connect     = (1_u64 << 57) | 0x0000000080000000_u64
      Getpeername = (1_u64 << 57) | 0x0000000100000000_u64
      Getsockname = (1_u64 << 57) | 0x0000000200000000_u64
      Getsockopt  = (1_u64 << 57) | 0x0000000400000000_u64
      Listen      = (1_u64 << 57) | 0x0000000800000000_u64
      Peeloff     = (1_u64 << 57) | 0x0000001000000000_u64
      Setsockopt  = (1_u64 << 57) | 0x0000002000000000_u64
      Shutdown    = (1_u64 << 57) | 0x0000004000000000_u64
      # *at path rights (index 0; each implies Lookup per the header macros).
      Bindat    = (1_u64 << 57) | (0x0000000000000400_u64 | 0x0000008000000000_u64)
      Connectat = (1_u64 << 57) | (0x0000000000000400_u64 | 0x0000010000000000_u64)
      Symlinkat = (1_u64 << 57) | (0x0000000000000400_u64 | 0x0000000008000000_u64)
      Unlinkat  = (1_u64 << 57) | (0x0000000000000400_u64 | 0x0000000010000000_u64)

      # Index 1 rights (bits per <sys/capsicum.h>).
      Event        = (1_u64 << 58) | 0x0000000000000020_u64
      KqueueEvent  = (1_u64 << 58) | 0x0000000000000040_u64
      KqueueChange = (1_u64 << 58) | 0x0000000000100000_u64

      # Coerce a `Symbol` or `Right` to a `Right`. Symbols name members
      # case-insensitively with `_` word separators (`:seek_tell` → `SeekTell`,
      # `:kqueue_event` → `KqueueEvent`). A `Right` is returned unchanged.
      # Raises `ArgumentError` naming the bad symbol when it matches no member.
      #
      # Used wherever rights are accepted so callers can write `:read` instead
      # of `Right::Read` (e.g. `Rights.new(:read, :fstat)`).
      def self.from(value : Symbol | Right) : Right
        case value
        in Right  then value
        in Symbol then parse(value.to_s)
        end
      end
    end

    # A set of Capsicum rights that can be applied to a file descriptor.
    # Wraps `cap_rights_t`.
    struct Rights
      @raw : LibCapsicum::CapRights

      # Build an empty rights set.
      def initialize
        @raw = LibCapsicum::CapRights.new
      end

      # Build a rights set seeded with the given rights. Each may be a `Right`
      # or a `Symbol` naming one (`Rights.new(:read, :fstat)`).
      def initialize(*rights : Symbol | Right)
        @raw = LibCapsicum::CapRights.new
        set(*rights)
      end

      def to_unsafe : LibCapsicum::CapRights*
        pointerof(@raw)
      end

      # Add rights. Each may be a `Right` or a `Symbol` naming one
      # (`set(:accept, :listen)`). Returns self.
      def set(*rights : Symbol | Right) : self
        add_raw(rights.map { |r| Right.from(r).value }.to_a)
      end

      # Add rights given as raw uint64 values. Used for rights not enumerated
      # in `Right`; prefer `#set` for named rights.
      def add_raw(rights : Enumerable(UInt64)) : self
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          # Initialize once if uninitialized, then add each right.
          # __cap_rights_init wants the terminating 0_u64.
          if @raw.cr_rights[0] == 0 && @raw.cr_rights[1] == 0
            LibCapsicum.__cap_rights_init(LibCapsicum::CAP_RIGHTS_VERSION, pointerof(@raw), 0_u64)
          end
          rights.each do |bits|
            LibCapsicum.__cap_rights_set(pointerof(@raw), bits, 0_u64)
          end
          self
        {% else %}
          raise UnsupportedPlatformError.new
        {% end %}
      end

      # Remove rights. Each may be a `Right` or a `Symbol` naming one.
      # Returns self.
      def clear(*rights : Symbol | Right) : self
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          rights.each do |r|
            LibCapsicum.__cap_rights_clear(pointerof(@raw), Right.from(r).value, 0_u64)
          end
          self
        {% else %}
          raise UnsupportedPlatformError.new
        {% end %}
      end

      # True if `right` is present in this rights set. Accepts a `Right` or a
      # `Symbol` naming one.
      def includes?(right : Symbol | Right) : Bool
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          LibCapsicum.__cap_rights_is_set(pointerof(@raw), Right.from(right).value, 0_u64)
        {% else %}
          raise UnsupportedPlatformError.new
        {% end %}
      end

      # True if the internal `cap_rights_t` passes `cap_rights_is_valid(3)`.
      # A freshly-constructed empty `Rights` returns true; a zero-filled struct does not.
      def valid? : Bool
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          LibCapsicum.cap_rights_is_valid(pointerof(@raw))
        {% else %}
          false
        {% end %}
      end

      # Apply these rights as the hard limit for the raw descriptor `fd`.
      # Use this for fd-bearing handles that aren't `IO::FileDescriptor`,
      # e.g. a `Socket` (`rights.apply_to(server.fd)`).
      def apply_to(fd : Int32) : Nil
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          if LibCapsicum.cap_rights_limit(fd, pointerof(@raw)) != 0
            raise Error.from_errno("cap_rights_limit")
          end
        {% else %}
          raise UnsupportedPlatformError.new
        {% end %}
      end

      # Apply these rights as the hard limit for `io`.
      def apply_to(io : IO::FileDescriptor) : Nil
        apply_to(io.fd)
      end

      # Current effective rights of the raw descriptor `fd`. Use for fd-bearing
      # handles that aren't `IO::FileDescriptor`, e.g. a `Socket`.
      def self.of(fd : Int32) : Rights
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          r = Rights.new
          if LibCapsicum.__cap_rights_get(LibCapsicum::CAP_RIGHTS_VERSION, fd, pointerof(r.@raw)) != 0
            raise Error.from_errno("cap_rights_get")
          end
          r
        {% else %}
          raise UnsupportedPlatformError.new
        {% end %}
      end

      # Current effective rights of `io`.
      def self.of(io : IO::FileDescriptor) : Rights
        of(io.fd)
      end
    end

    # Bitmask passed to `Capability.limit_fcntls` — bitwise-OR of
    # `CAP_FCNTL_GETFL`, `CAP_FCNTL_SETFL`, `CAP_FCNTL_GETOWN`,
    # `CAP_FCNTL_SETOWN`.
    @[Flags]
    enum FcntlMask : UInt32
      GetFl  = 0x08
      SetFl  = 0x10
      GetOwn = 0x20
      SetOwn = 0x40
    end

    # Restrict the ioctl(2) commands allowed on `io`. Pass an empty array to
    # forbid all ioctls.
    def self.limit_ioctls(io : IO::FileDescriptor, cmds : Enumerable(UInt64)) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        arr = cmds.map(&.to_u64).to_a
        ptr = arr.empty? ? Pointer(LibC::ULong).null : arr.to_unsafe.as(LibC::ULong*)
        if LibCapsicum.cap_ioctls_limit(io.fd, ptr, arr.size.to_u64) != 0
          raise Error.from_errno("cap_ioctls_limit")
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict fcntl(2) commands. See `FcntlMask`.
    def self.limit_fcntls(io : IO::FileDescriptor, mask : FcntlMask) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        if LibCapsicum.cap_fcntls_limit(io.fd, mask.value) != 0
          raise Error.from_errno("cap_fcntls_limit")
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end
  end
end
