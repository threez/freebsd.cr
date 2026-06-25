module FreeBSD::Sandbox
  # :nodoc:
  # Runtime privilege-drop configuration collected from the `user` directive of
  # a `Sandbox.define` block. Holds the resolved drop target until the setup
  # phase has opened every resource; `#drop!` then performs the drop in the one
  # safe order via `FreeBSD::Privdrop.drop`.
  #
  # A `nil` config means "no privilege drop was declared" — `#drop!` is a no-op.
  struct PrivdropConfig
    getter username : String?
    getter uid : LibC::UidT?
    getter gid : LibC::GidT?
    getter chroot : String?
    getter? scrub_env : Bool

    def initialize(@username : String? = nil,
                   @uid : LibC::UidT? = nil,
                   @gid : LibC::GidT? = nil,
                   @chroot : String? = nil,
                   @scrub_env : Bool = true)
    end

    # Perform the privilege drop. Delegates to `FreeBSD::Privdrop.drop`, which
    # runs groups → chroot → setgid → setuid → scrub in the mandatory order.
    # Resolving by username goes through `getpwnam(3)`, so this must run before
    # `cap_enter`.
    def drop! : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        if (u = @uid) && (g = @gid)
          FreeBSD::Privdrop.drop(uid: u, gid: g, username: @username,
            chroot: @chroot, scrub_env: @scrub_env)
        elsif name = @username
          FreeBSD::Privdrop.drop(name, chroot: @chroot, scrub_env: @scrub_env)
        else
          # No uid/gid/username given — nothing to drop, but honour chroot/scrub
          # if the caller asked for them on their own.
          FreeBSD::Privdrop.chroot(@chroot.not_nil!) if @chroot
          FreeBSD::Privdrop::Env.scrub if @scrub_env && @chroot
        end
      {% else %}
        raise ::FreeBSD::Privdrop::UnsupportedPlatformError.new
      {% end %}
    end
  end
end
