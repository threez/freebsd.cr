require "../spec_helper"
require "../../src/freebsd/casper/fileargs"

describe FreeBSD::Casper::Service::FileArgs do
  it_on_capsicum "opens a declared path from a sandboxed child" do
    in_sandbox_child do
      fa = FreeBSD::Casper::Service::FileArgs.create(["/etc/hosts"], flags: LibC::O_RDONLY)
      FreeBSD::Capsicum.sandbox!
      fa.open_fd("/etc/hosts").should be > 0
    end
  end

  it_on_capsicum "lstats a declared path under sandbox" do
    in_sandbox_child do
      fa = FreeBSD::Casper::Service::FileArgs.create(["/etc/hosts"],
        flags: LibC::O_RDONLY,
        fa_flags: FreeBSD::Casper::Service::FileArgs::OPEN | FreeBSD::Casper::Service::FileArgs::LSTAT)
      FreeBSD::Capsicum.sandbox!
      info = fa.lstat("/etc/hosts")
      info.should_not be_nil
      info.try { |i| i.size.should be > 0 }
    end
  end

  it_on_capsicum "realpath resolves a declared path under sandbox" do
    in_sandbox_child do
      fa = FreeBSD::Casper::Service::FileArgs.create(["/etc/hosts"],
        flags: LibC::O_RDONLY,
        fa_flags: FreeBSD::Casper::Service::FileArgs::OPEN | FreeBSD::Casper::Service::FileArgs::REALPATH)
      FreeBSD::Capsicum.sandbox!
      fa.realpath("/etc/hosts").should start_with("/")
    end
  end

  it_on_capsicum "open_file returns a real ::File with the path preserved" do
    in_sandbox_child do
      fa = FreeBSD::Casper::Service::FileArgs.create(["/etc/hosts"], flags: LibC::O_RDONLY)
      FreeBSD::Capsicum.sandbox!
      file = fa.open_file("/etc/hosts")
      file.should be_a(::File)
      file.path.should eq("/etc/hosts")
      file.gets_to_end.should_not be_empty
      file.close
    end
  end

  it_on_capsicum "refuses paths that were not declared" do
    in_sandbox_child do
      fa = FreeBSD::Casper::Service::FileArgs.create(["/etc/hosts"], flags: LibC::O_RDONLY)
      FreeBSD::Capsicum.sandbox!
      expect_raises(::File::Error) { fa.open_fd("/etc/passwd") }
    end
  end
end
