class ::File
  # :nodoc:
  # Construct a `::File` directly from an already-open fd while preserving the
  # path metadata. Used by the Capsicum/Casper file helpers (`Directory#open`,
  # `Casper::Service::FileArgs#open_file`) so a helper-opened fd surfaces as a
  # real `::File` (with `.path`, `.info`, full buffered IO) rather than a bare
  # `IO::FileDescriptor`. Mirrors the private `File#initialize(@path, fd, mode, ...)`
  # constructor.
  def self.from_fd(path : String, fd : Int32, mode : String = "r") : self
    new(path, fd, mode, blocking: true)
  end
end
