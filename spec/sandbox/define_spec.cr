require "../spec_helper"
require "../../src/freebsd/sandbox"

# Note: a `FreeBSD::Sandbox.define` block ends in `cap_enter`, which is one-way
# per process — so it cannot run inline in the spec runner. Full `define`
# behaviour (typed accessors, helper-child guard, sandboxing) is exercised by
# building and running a fixture subprocess; see `compose_spec.cr`. Here we test
# the pure privdrop-config builder, which has no syscall side effects.
describe FreeBSD::Sandbox::PrivdropConfig do
  it "carries the username form" do
    cfg = FreeBSD::Sandbox.__privdrop_config("nobody", chroot: "/var/empty")
    cfg.username.should eq("nobody")
    cfg.chroot.should eq("/var/empty")
    cfg.scrub_env.should be_true
    cfg.uid.should be_nil
  end

  it "carries the uid/gid form" do
    cfg = FreeBSD::Sandbox.__privdrop_config(
      uid: 65534_u32, gid: 65534_u32, scrub_env: false)
    cfg.uid.should eq(65534_u32)
    cfg.gid.should eq(65534_u32)
    cfg.scrub_env.should be_false
    cfg.username.should be_nil
  end
end
