# Low-level libc bindings for privilege-drop syscalls not already declared
# in Crystal's stdlib LibC.
#
# Already in LibC (x86_64-freebsd, x86_64-dragonfly, and others):
#   chroot(2)  — LibC.chroot
#   chdir(2)   — LibC.chdir
#   getuid(2)  — LibC.getuid
#   setuid(2)  — LibC.setuid
#
# The three below are absent and must be declared here.

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("c")]
  lib LibPrivdrop
    # setgid(2) — set real, effective, and saved-set group ID.
    fun setgid(gid : LibC::GidT) : Int32

    # setgroups(2) — replace the supplementary group list.
    # Pass ngroups=0 and gidset=NULL to clear all supplementary groups.
    fun setgroups(ngroups : Int32, gidset : LibC::GidT*) : Int32

    # initgroups(3) — build supplementary group list from /etc/group and
    # call setgroups(2). basegid is the primary GID (from the passwd entry)
    # and is always included in the result.
    fun initgroups(name : LibC::Char*, basegid : LibC::GidT) : Int32
  end
{% end %}
