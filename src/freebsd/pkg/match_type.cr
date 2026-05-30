module FreeBSD::Pkg
  # How a pattern argument is interpreted by query methods.
  enum MatchType : Int32
    # Match all packages — pattern is ignored.
    All = 0
    # Exact string equality on the relevant field.
    Exact = 1
    # Shell-style glob (`*`, `?`, `[…]`) on the relevant field.
    Glob = 2
    # POSIX extended regular expression on the relevant field.
    Regex = 3
  end

  # Field to search or sort by in `Database#search`.
  enum SearchField : Int32
    # No field / no sort.
    None = 0
    # Port origin (e.g. `www/nginx`).
    Origin = 1
    # Package name only.
    Name = 2
    # Package name and version string (e.g. `nginx-1.26.1,3`).
    NameVer = 3
    # One-line package comment.
    Comment = 4
    # Full package description.
    Desc = 5
    # Comment and description combined.
    CommentDesc = 6
    # Port flavour.
    Flavor = 7
  end
end
