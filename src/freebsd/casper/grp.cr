require "../casper"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_grp")]
  lib LibCapGrp
    struct Group
      gr_name : LibC::Char*
      gr_passwd : LibC::Char*
      gr_gid : UInt32
      gr_mem : LibC::Char**
    end

    fun cap_getgrnam(chan : LibCasper::CapChannel, name : LibC::Char*) : Group*
    fun cap_getgrgid(chan : LibCasper::CapChannel, gid : UInt32) : Group*

    fun cap_grp_limit_cmds(chan : LibCasper::CapChannel, cmds : LibC::Char**, ncmds : LibC::SizeT) : Int32
    fun cap_grp_limit_fields(chan : LibCasper::CapChannel, fields : LibC::Char**, nfields : LibC::SizeT) : Int32
    fun cap_grp_limit_groups(chan : LibCasper::CapChannel,
                             names : LibC::Char**, nnames : LibC::SizeT,
                             gids : UInt32*, ngids : LibC::SizeT) : Int32
  end
{% end %}

module FreeBSD::Casper
  class Service::Grp < Service
    # A group entry from the group database. Mirrors `struct group` from `<grp.h>`.
    record Group,
      name : String,
      gid : UInt32,
      members : Array(String)

    # Look up a group by name. Returns `nil` if not found.
    def getgrnam(name : String) : Group?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptr = LibCapGrp.cap_getgrnam(@handle, name)
        ptr.null? ? nil : to_group(ptr.value)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Look up a group by GID. Returns `nil` if not found.
    def getgrgid(gid : UInt32 | Int32) : Group?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptr = LibCapGrp.cap_getgrgid(@handle, gid.to_u32)
        ptr.null? ? nil : to_group(ptr.value)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict which commands this service may execute ("getgrnam", "getgrgid", ...).
    def limit_cmds(*cmds : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptrs = cmds.map(&.to_unsafe).to_a
        ptr = ptrs.empty? ? Pointer(LibC::Char*).null : ptrs.to_unsafe
        if LibCapGrp.cap_grp_limit_cmds(@handle, ptr, ptrs.size.to_u64) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_grp_limit_cmds")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict which fields are returned ("gr_name", "gr_gid", "gr_mem", ...).
    def limit_fields(*fields : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        ptrs = fields.map(&.to_unsafe).to_a
        ptr = ptrs.empty? ? Pointer(LibC::Char*).null : ptrs.to_unsafe
        if LibCapGrp.cap_grp_limit_fields(@handle, ptr, ptrs.size.to_u64) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_grp_limit_fields")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Restrict lookups to specific group names and/or GIDs.
    # Pass empty enumerables to clear all group restrictions.
    def limit_groups(names : Enumerable(String) = [] of String,
                     gids : Enumerable(UInt32) = [] of UInt32) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        name_ptrs = names.map(&.to_unsafe).to_a
        gid_arr = gids.map(&.to_u32).to_a
        rc = LibCapGrp.cap_grp_limit_groups(@handle,
          name_ptrs.empty? ? Pointer(LibC::Char*).null : name_ptrs.to_unsafe,
          name_ptrs.size.to_u64,
          gid_arr.empty? ? Pointer(UInt32).null : gid_arr.to_unsafe,
          gid_arr.size.to_u64)
        if rc != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_grp_limit_groups")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      private def to_group(g : LibCapGrp::Group) : Group
        members = [] of String
        unless g.gr_mem.null?
          i = 0
          loop do
            p = g.gr_mem[i]
            break if p.null?
            members << String.new(p)
            i += 1
          end
        end
        Group.new(
          name: String.new(g.gr_name),
          gid: g.gr_gid,
          members: members,
        )
      end
    {% end %}
  end

  class Channel
    # Open the `system.grp` Casper service on this channel.
    def grp : Service::Grp
      Service::Grp.new(service("system.grp"))
    end
  end
end
