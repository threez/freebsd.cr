require "../spec_helper"
require "../../src/freebsd/capsicum/integrate/file"
require "../../src/freebsd/capsicum/integrate/dir"
require "file_utils"

private def with_tmpdir(&)
  dir = File.tempname("capdir", "")
  Dir.mkdir(dir)
  begin
    yield dir
  ensure
    FileUtils.rm_rf(dir) rescue nil
  end
end

describe FreeBSD::Capsicum::Directory do
  it_on_capsicum "openat reads a file beneath a pre-opened directory after cap_enter" do
    with_tmpdir do |tmp|
      File.write(File.join(tmp, "file.txt"), "hello openat")
      in_sandbox_child do
        dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
        FreeBSD::Capsicum.sandbox!

        # open_file/open parity: a real ::File with .path set.
        dir.open("file.txt") do |f|
          f.should be_a(::File)
          f.path.should eq(File.join(dir.base, "file.txt"))
          f.gets_to_end.should eq("hello openat")
        end

        # open_io and open_fd reach the same bytes.
        io = dir.open_io("file.txt")
        io.gets_to_end.should eq("hello openat")
        io.close

        fd = dir.open_fd("file.txt")
        (fd >= 0).should be_true
        LibC.close(fd)
      end
    end
  end

  it_on_capsicum "honors the directory's rights: write needs write/create, read-only rejects it" do
    with_tmpdir do |tmp|
      File.write(File.join(tmp, "seed.txt"), "x")
      in_sandbox_child do
        rw = FreeBSD::Capsicum::Directory.open(tmp,
          rights: [:lookup, :read, :write, :create, :fstat, :ftruncate])
        ro = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
        FreeBSD::Capsicum.sandbox!

        rw.open("new.txt", "w", &.print("written"))
        rw.open("new.txt") { |f| f.gets_to_end.should eq("written") }

        expect_raises(File::Error) { ro.open("seed.txt", "w") { } }
      end
    end
  end

  it_on_capsicum "rejects '..' escapes and absolute paths in capability mode" do
    with_tmpdir do |tmp|
      in_sandbox_child do
        dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
        FreeBSD::Capsicum.sandbox!

        expect_raises(File::Error) { dir.open("../#{File.basename(tmp)}/../etc/hosts") { } }
        expect_raises(File::Error) { dir.open("/etc/hosts") { } }
      end
    end
  end

  it_on_capsicum "limits the directory fd's rights (round-trips via cap_rights_get)" do
    with_tmpdir do |tmp|
      dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:read, :fstat])
      begin
        got = dir.rights
        got.includes?(:read).should be_true
        got.includes?(:lookup).should be_true # always unioned in
        got.includes?(:write).should be_false
      ensure
        dir.close
      end
    end
  end

  describe "transparent File.open routing" do
    it_on_capsicum "routes paths beneath a registered directory through openat" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "page.html"), "routed")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
          FreeBSD::Capsicum.register_directory(dir)
          FreeBSD::Capsicum.sandbox!

          File.read(File.join(tmp, "page.html")).should eq("routed")
          # An unregistered path is not routable in capability mode.
          expect_raises(File::Error) { File.read("/etc/hosts") }
        ensure
          FreeBSD::Capsicum.clear_directories
        end
      end
    end
  end

  describe ".directory_for" do
    it_on_capsicum "longest-prefix matches and respects path boundaries" do
      with_tmpdir do |root|
        # root/, root/sub/ — register both; the deeper one must win.
        sub = File.join(root, "sub")
        Dir.mkdir(sub)
        outer = FreeBSD::Capsicum::Directory.open(root, rights: [:lookup, :read])
        inner = FreeBSD::Capsicum::Directory.open(sub, rights: [:lookup, :read])
        begin
          FreeBSD::Capsicum.register_directory(outer)
          FreeBSD::Capsicum.register_directory(inner)

          # A path under sub resolves to the inner (longest) base.
          match = FreeBSD::Capsicum.directory_for(File.join(sub, "x.txt"))
          match.should_not be_nil
          d, rel = match.not_nil!
          d.base.should eq(inner.base)
          rel.should eq("x.txt")

          # A path under root-but-not-sub resolves to the outer base.
          match2 = FreeBSD::Capsicum.directory_for(File.join(root, "y.txt"))
          match2.not_nil![0].base.should eq(outer.base)

          # A sibling that merely shares a string prefix does not match.
          FreeBSD::Capsicum.directory_for("#{root}x/z.txt").should be_nil

          # An unrelated path matches nothing.
          FreeBSD::Capsicum.directory_for("/nonexistent/elsewhere").should be_nil
        ensure
          FreeBSD::Capsicum.clear_directories
          outer.close
          inner.close
        end
      end
    end
  end

  describe "#info? / #exists?" do
    it_on_capsicum "stats files beneath the directory via fstatat after cap_enter" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "file.txt"), "1234567")
        Dir.mkdir(File.join(tmp, "sub"))
        File.symlink("file.txt", File.join(tmp, "link"))
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
          FreeBSD::Capsicum.sandbox!

          dir.info?("file.txt").not_nil!.size.should eq(7)
          dir.info?("missing").should be_nil
          dir.info?("sub").not_nil!.directory?.should be_true

          # follow vs nofollow on a symlink to the 7-byte file.
          dir.info?("link", follow_symlinks: true).not_nil!.file?.should be_true
          dir.info?("link", follow_symlinks: false).not_nil!.symlink?.should be_true
        end
      end
    end

    it_on_capsicum "exists? reports presence and treats escapes as absent" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "file.txt"), "x")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
          FreeBSD::Capsicum.sandbox!

          dir.exists?("file.txt").should be_true
          dir.exists?("nope").should be_false
          dir.exists?("../etc/hosts").should be_false # resolve-beneath, not raise
        end
      end
    end

    it_on_capsicum "routes File.info? / File.exists? through the registered directory" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "page.html"), "hello")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
          FreeBSD::Capsicum.register_directory(dir)
          FreeBSD::Capsicum.sandbox!

          File.exists?(File.join(tmp, "page.html")).should be_true
          File.info?(File.join(tmp, "page.html")).not_nil!.size.should eq(5)
          # Unregistered path: not routed; exists? is false in cap mode (no crash).
          File.exists?("/etc/hosts").should be_false
        ensure
          FreeBSD::Capsicum.clear_directories
        end
      end
    end

    it_on_capsicum "info? requires :fstat (exact_rights without it raises)" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "file.txt"), "x")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp,
            rights: [:lookup, :read], exact_rights: true)
          FreeBSD::Capsicum.sandbox!
          expect_raises(File::Error) { dir.info?("file.txt") }
        end
      end
    end
  end

  describe "#delete / #delete?" do
    it_on_capsicum "unlinks files beneath the dir fd via unlinkat after cap_enter" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "gone.txt"), "x")
        File.write(File.join(tmp, "keep.txt"), "y")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp,
            rights: [:lookup, :read, :fstat, :unlinkat])
          FreeBSD::Capsicum.sandbox!

          dir.delete("gone.txt").should be_true
          dir.exists?("gone.txt").should be_false
          dir.exists?("keep.txt").should be_true

          # Missing file: delete? is a no-op false; delete raises.
          dir.delete?("missing").should be_false
          expect_raises(File::Error) { dir.delete("missing") }

          # Escapes are rejected in-kernel (resolve-beneath), not allowed through.
          expect_raises(File::Error) { dir.delete("../keep.txt") }
        end
      end
    end

    it_on_capsicum "routes File.delete / File.delete? through the registered directory" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "a.txt"), "1")
        File.write(File.join(tmp, "b.txt"), "2")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp,
            rights: [:lookup, :read, :fstat, :unlinkat])
          FreeBSD::Capsicum.register_directory(dir)
          FreeBSD::Capsicum.sandbox!

          File.delete(File.join(tmp, "a.txt"))
          File.exists?(File.join(tmp, "a.txt")).should be_false

          File.delete?(File.join(tmp, "b.txt")).should be_true
          File.delete?(File.join(tmp, "b.txt")).should be_false # already gone


        ensure
          FreeBSD::Capsicum.clear_directories
        end
      end
    end

    it_on_capsicum "delete requires :unlinkat (exact_rights without it raises)" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "file.txt"), "x")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp,
            rights: [:lookup, :read, :fstat], exact_rights: true)
          FreeBSD::Capsicum.sandbox!
          expect_raises(File::Error) { dir.delete("file.txt") }
        end
      end
    end
  end

  describe "#entries / #children / #each_child" do
    it_on_capsicum "lists directory contents beneath the dir fd after cap_enter" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "a.txt"), "")
        File.write(File.join(tmp, "b.txt"), "")
        Dir.mkdir(File.join(tmp, "sub"))
        File.write(File.join(tmp, "sub", "c.txt"), "")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
          FreeBSD::Capsicum.sandbox!

          dir.children.sort.should eq(["a.txt", "b.txt", "sub"])
          dir.entries.includes?(".").should be_true
          dir.entries.includes?("..").should be_true

          seen = [] of String
          dir.each_child { |n| seen << n }
          seen.sort.should eq(["a.txt", "b.txt", "sub"])

          dir.children("sub").should eq(["c.txt"])
        end
      end
    end

    it_on_capsicum "routes Dir.children / Dir.entries, including the base root itself" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "a.txt"), "")
        File.write(File.join(tmp, "b.txt"), "")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:lookup, :read, :fstat])
          FreeBSD::Capsicum.register_directory(dir)
          FreeBSD::Capsicum.sandbox!

          Dir.children(tmp).sort.should eq(["a.txt", "b.txt"])
          Dir.entries(tmp).includes?("..").should be_true
        ensure
          FreeBSD::Capsicum.clear_directories
        end
      end
    end

    it_on_capsicum "listing requires :read (exact_rights without it raises)" do
      with_tmpdir do |tmp|
        File.write(File.join(tmp, "a.txt"), "")
        in_sandbox_child do
          dir = FreeBSD::Capsicum::Directory.open(tmp,
            rights: [:lookup, :fstat], exact_rights: true)
          FreeBSD::Capsicum.sandbox!
          expect_raises(File::Error) { dir.children }
        end
      end
    end
  end

  describe "rights ergonomics" do
    it_on_capsicum "exact_rights: true applies exactly the listed rights (no union)" do
      with_tmpdir do |tmp|
        exact = FreeBSD::Capsicum::Directory.open(tmp, rights: [:read], exact_rights: true)
        begin
          exact.rights.includes?(:read).should be_true
          exact.rights.includes?(:lookup).should be_false # no union
          exact.rights.includes?(:fstat).should be_false
        ensure
          exact.close
        end
      end
    end

    it_on_capsicum "default (non-exact) rights union in :lookup/:fcntl/:fstat/:seek" do
      with_tmpdir do |tmp|
        dir = FreeBSD::Capsicum::Directory.open(tmp, rights: [:read])
        begin
          dir.rights.includes?(:read).should be_true
          dir.rights.includes?(:lookup).should be_true
          dir.rights.includes?(:fstat).should be_true
          dir.rights.includes?(:seek).should be_true
        ensure
          dir.close
        end
      end
    end

    it_on_capsicum "exact_rights: true without rights: raises ArgumentError" do
      with_tmpdir do |tmp|
        expect_raises(ArgumentError) do
          FreeBSD::Capsicum::Directory.open(tmp, exact_rights: true)
        end
      end
    end
  end
end
