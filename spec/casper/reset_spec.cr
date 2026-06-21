require "../spec_helper"
require "../../src/freebsd/casper/net"
require "../../src/freebsd/casper/grp"
require "../../src/freebsd/casper/pwd"
require "../../src/freebsd/casper/sysctl"

# `FreeBSD::Casper.reset!` drops every installed service handle by running the
# callbacks each service file registers via `on_reset`. This is the mechanism
# that lets helper children shed the Casper handles they inherit across a
# pdfork/fork, which in turn makes `register_*` macro ordering irrelevant.
describe "FreeBSD::Casper.reset!" do
  it "is a no-op (and does not raise) when no service is installed" do
    FreeBSD::Casper.reset!
    FreeBSD::Casper.net?.should be_nil
    FreeBSD::Casper.grp?.should be_nil
    FreeBSD::Casper.pwd?.should be_nil
    FreeBSD::Casper.sysctl?.should be_nil
  end

  it "runs every registered reset hook" do
    fired = 0
    FreeBSD::Casper.on_reset { fired += 1 }
    FreeBSD::Casper.on_reset { fired += 1 }
    before = fired
    FreeBSD::Casper.reset!
    (fired - before).should be >= 2
  end

  # End-to-end: a real forked helper must NOT see the net handle the parent
  # installed before the fork. This is the exact deadlock the fix prevents —
  # without the fork-time reset! the child would inherit @@net and route DNS
  # through the parent's channel (recursive/invalid, EDEADLK). The helper
  # reports back what it observed so we assert on the child's actual state.
  #
  # The handle wraps a real `cap_init` channel (not a null pointer) so the
  # service's `cap_close` finalizer is safe; we never use it for networking —
  # the test only checks whether `net?` is nil in the child vs parent. The
  # `system.net` service plugin need not be installed for this.
  it_on_capsicum "a forked helper does not inherit the parent's installed net handle" do
    # Back the installed Service::Net with a real cap_init handle owned solely
    # by the Service (its cap_close finalizer is the only closer — a double
    # cap_close on the same handle aborts the process). The handle is never
    # used for networking; the test only inspects whether net? is nil.
    svc = FreeBSD::Casper::Service::Net.new(LibCasper.cap_init)
    FreeBSD::Casper.install_net(svc)
    FreeBSD::Casper.net?.should_not be_nil # sanity: parent has it installed
    begin
      in_sandbox_child do
        client = FreeBSD::Casper::Helper.spawn do |server|
          server.serve do |op, _payload|
            case op
            when "net_installed?"
              (FreeBSD::Casper.net? ? "yes" : "no").to_slice
            else
              raise "unknown op: #{op}"
            end
          end
        end
        begin
          # The parent installed @@net; the child must have had it cleared by
          # the fork-time reset!.
          String.new(client.request("net_installed?")).should eq("no")
        ensure
          client.close
        end
      end
    ensure
      FreeBSD::Casper.uninstall_net
      svc.close
    end
  end
end
