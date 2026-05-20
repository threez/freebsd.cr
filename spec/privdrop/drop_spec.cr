require "../spec_helper"
require "../../src/freebsd/privdrop"

describe FreeBSD::Privdrop do
  it "reports SUPPORTED correctly" do
    FreeBSD::Privdrop::SUPPORTED.should eq(CAPSICUM_OS)
  end

  describe "on non-FreeBSD platforms" do
    unless CAPSICUM_OS
      it "setuid raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Privdrop::UnsupportedPlatformError) do
          FreeBSD::Privdrop.setuid(0_u32)
        end
      end

      it "setgid raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Privdrop::UnsupportedPlatformError) do
          FreeBSD::Privdrop.setgid(0_u32)
        end
      end

      it "clear_groups raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Privdrop::UnsupportedPlatformError) do
          FreeBSD::Privdrop.clear_groups
        end
      end

      it "chroot raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Privdrop::UnsupportedPlatformError) do
          FreeBSD::Privdrop.chroot("/var/empty")
        end
      end

      it "drop raises UnsupportedPlatformError" do
        expect_raises(FreeBSD::Privdrop::UnsupportedPlatformError) do
          FreeBSD::Privdrop.drop(uid: 0_u32, gid: 0_u32)
        end
      end
    end
  end

  describe "Env" do
    it "scrub removes LD_PRELOAD and resets PATH" do
      old_path = ENV["PATH"]?
      ENV["LD_PRELOAD"] = "/evil.so"
      ENV["PATH"] = "/attacker/bin:/usr/bin"

      removed = FreeBSD::Privdrop::Env.scrub

      removed.should contain("LD_PRELOAD")
      ENV["LD_PRELOAD"]?.should be_nil
      ENV["PATH"].should eq(FreeBSD::Privdrop::Env::SAFE_PATH)
    ensure
      ENV.delete("LD_PRELOAD")
      ENV["PATH"] = old_path if old_path
    end

    it "scrub does not raise when dangerous vars are absent" do
      FreeBSD::Privdrop::Env::DANGEROUS_VARS.each { |k| ENV.delete(k) }
      removed = FreeBSD::Privdrop::Env.scrub
      # PATH was reset; everything else was already absent
      removed.should be_empty
      ENV["PATH"].should eq(FreeBSD::Privdrop::Env::SAFE_PATH)
    end

    it "delete returns true when the var existed" do
      ENV["TEST_PRIVDROP_VAR"] = "1"
      FreeBSD::Privdrop::Env.delete("TEST_PRIVDROP_VAR").should be_true
      ENV["TEST_PRIVDROP_VAR"]?.should be_nil
    end

    it "delete returns false when the var did not exist" do
      ENV.delete("TEST_PRIVDROP_VAR")
      FreeBSD::Privdrop::Env.delete("TEST_PRIVDROP_VAR").should be_false
    end

    it "reset_path returns the old value and sets SAFE_PATH" do
      ENV["PATH"] = "/custom/bin"
      old = FreeBSD::Privdrop::Env.reset_path
      old.should eq("/custom/bin")
      ENV["PATH"].should eq(FreeBSD::Privdrop::Env::SAFE_PATH)
    end
  end

  # Syscall tests on FreeBSD — without root, each raises PermissionError.
  it_on_capsicum "clear_groups raises PermissionError without root" do
    in_sandbox_child do
      next if LibC.getuid == 0
      expect_raises(FreeBSD::Privdrop::PermissionError) do
        FreeBSD::Privdrop.clear_groups
      end
    end
  end

  it_on_capsicum "setgid raises PermissionError without root" do
    in_sandbox_child do
      next if LibC.getuid == 0
      expect_raises(FreeBSD::Privdrop::PermissionError) do
        FreeBSD::Privdrop.setgid(0_u32)
      end
    end
  end

  it_on_capsicum "setuid raises PermissionError without root" do
    in_sandbox_child do
      next if LibC.getuid == 0
      expect_raises(FreeBSD::Privdrop::PermissionError) do
        FreeBSD::Privdrop.setuid(0_u32)
      end
    end
  end

  it_on_capsicum "chroot raises PermissionError without root" do
    in_sandbox_child do
      next if LibC.getuid == 0
      expect_raises(FreeBSD::Privdrop::PermissionError) do
        FreeBSD::Privdrop.chroot("/var/empty")
      end
    end
  end

  it_on_capsicum "drop(uid:, gid:) raises PermissionError without root" do
    in_sandbox_child do
      next if LibC.getuid == 0
      expect_raises(FreeBSD::Privdrop::PermissionError) do
        FreeBSD::Privdrop.drop(uid: 65534_u32, gid: 65534_u32, scrub_env: false)
      end
    end
  end

  # Root-only integration: actually drop to nobody and verify getuid.
  it_on_capsicum "drop to nobody succeeds when running as root" do
    next unless LibC.getuid == 0
    in_sandbox_child do
      FreeBSD::Privdrop.drop(uid: 65534_u32, gid: 65534_u32, scrub_env: false)
      LibC.getuid.should eq(65534_u32)
    end
  end
end
