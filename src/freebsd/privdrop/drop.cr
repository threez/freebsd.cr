require "./errors"
require "./lib_privdrop"
require "./env"

module FreeBSD::Privdrop
  # Change the process root directory. Must be called as root (UID 0) and
  # before `setuid`. After chroot the working directory is moved to "/" inside
  # the new root automatically.
  #
  # Raises `PermissionError` when the process lacks privilege, `SystemError`
  # for all other failures.
  def self.chroot(path : String) : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if LibC.chroot(path) != 0
        raise Error.from_errno("chroot(#{path.inspect})")
      end
      if LibC.chdir("/") != 0
        raise Error.from_errno("chdir(\"/\") after chroot")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Replace the supplementary group list with an explicit set of GIDs.
  # Pass an empty enumerable to clear all supplementary groups.
  #
  # Raises `InvalidArgumentError` when the list exceeds `NGROUPS_MAX`,
  # `PermissionError` when the process is not root.
  def self.setgroups(gids : Enumerable(LibC::GidT)) : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      arr = gids.map(&.to_u32).to_a
      ptr = arr.empty? ? Pointer(LibC::GidT).null : arr.to_unsafe
      if LibPrivdrop.setgroups(arr.size.to_i32, ptr) != 0
        raise Error.from_errno("setgroups")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Clear all supplementary groups. Equivalent to `setgroups([])`.
  #
  # Raises `PermissionError` when the process is not root.
  def self.clear_groups : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if LibPrivdrop.setgroups(0, Pointer(LibC::GidT).null) != 0
        raise Error.from_errno("setgroups(0, NULL)")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Initialize supplementary groups via `initgroups(3)`: reads `/etc/group`
  # for *username* and calls `setgroups(2)` to install the resulting list.
  # *basegid* (the primary GID from the passwd entry) is always included.
  #
  # > **Note:** This reads `/etc/group` at call time. Call it **before**
  # > `chroot` unless the new root contains a valid `/etc/group`.
  #
  # Raises `PermissionError` when the process is not root.
  def self.init_groups(username : String, basegid : LibC::GidT) : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if LibPrivdrop.initgroups(username, basegid) != 0
        raise Error.from_errno("initgroups(#{username.inspect})")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Set the real, effective, and saved-set group ID. Must be called before
  # `setuid`.
  #
  # Raises `PermissionError` when the process is not root.
  def self.setgid(gid : LibC::GidT) : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if LibPrivdrop.setgid(gid) != 0
        raise Error.from_errno("setgid(#{gid})")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # Set the real, effective, and saved-set user ID. This permanently
  # relinquishes root when *uid* != 0. Must be the last privilege-drop step.
  #
  # Raises `PermissionError` when the process is not root and *uid* differs
  # from the current real UID.
  def self.setuid(uid : LibC::UidT) : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if LibC.setuid(uid) != 0
        raise Error.from_errno("setuid(#{uid})")
      end
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end

  # High-level privilege drop. Executes all steps in the mandatory safe order:
  #
  # 1. `init_groups(username, gid)` — if *username* given; else `clear_groups`.
  # 2. `chroot(chroot)` + `chdir("/")` — if *chroot* given.
  # 3. `setgid(gid)`
  # 4. `setuid(uid)` — permanently relinquishes root here.
  # 5. `Env.scrub` — if *scrub_env* is true (default).
  #
  # Open all file descriptors and Casper service channels **before** calling
  # this method. After `setuid` the process can no longer acquire new
  # privileges.
  #
  # > **Caveat:** `init_groups` reads `/etc/group` before `chroot`. If you
  # > supply both *username* and *chroot*, ensure `/etc/group` exists in the
  # > new root or use `setgroups([...])` explicitly before calling `drop`.
  def self.drop(uid : LibC::UidT, gid : LibC::GidT,
                username : String? = nil,
                chroot : String? = nil,
                scrub_env : Bool = true) : Nil
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      if name = username
        init_groups(name, gid)
      else
        clear_groups
      end
      if path = chroot
        self.chroot(path)
      end
      setgid(gid)
      setuid(uid)
      Env.scrub if scrub_env
    {% else %}
      raise UnsupportedPlatformError.new
    {% end %}
  end
end
