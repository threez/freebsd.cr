module FreeBSD::Pkg
  # Shared error-checking helpers for libpkg return codes.
  # Include this module in any class that calls libpkg functions.
  # Both instance methods and class methods gain access automatically.
  module PkgHelpers
    macro included
      extend PkgHelpers
    end

    # Converts a `Symbol` or `MatchType` value to `MatchType`.
    # `:all`, `:exact`, `:glob`, `:regex` are accepted as symbols.
    private def to_match_type(match : MatchType | Symbol) : MatchType
      case match
      when Symbol then MatchType.parse(match.to_s.camelcase)
      else             match
      end
    end

    # Converts a `Symbol`, `Array`, or `LoadFlags` value to `LoadFlags`.
    # Symbols must match flag names in snake_case (e.g. `:deps`, `:shlibs_required`).
    private def to_load_flags(flags : LoadFlags | Symbol | Array) : LoadFlags
      case flags
      when Symbol
        LoadFlags.parse(flags.to_s.camelcase)
      when Array
        flags.reduce(LoadFlags::None) do |acc, flag|
          acc | (flag.is_a?(Symbol) ? LoadFlags.parse(flag.to_s.camelcase) : flag.as(LoadFlags))
        end
      else
        flags
      end
    end

    # Converts a `Symbol`, `Array`, or `JobFlags` value to `JobFlags`.
    # Symbols must match flag names in snake_case (e.g. `:dry_run`, `:with_deps`).
    private def to_job_flags(flags : JobFlags | Symbol | Array) : JobFlags
      case flags
      when Symbol
        JobFlags.parse(flags.to_s.camelcase)
      when Array
        flags.reduce(JobFlags::None) do |acc, flag|
          acc | (flag.is_a?(Symbol) ? JobFlags.parse(flag.to_s.camelcase) : flag.as(JobFlags))
        end
      else
        flags
      end
    end

    # Raises `Error.from_pkg` unless *rc* is `EPKG_OK` (0).
    private def check_rc!(rc : Int32, fn : String) : Nil
      raise Error.from_pkg(rc, fn) unless rc == LibPkg::PkgErrorT::Ok.value
    end

    # Like `check_rc!` but also treats `EPKG_UP_TO_DATE` (9) as success.
    private def check_rc_or_uptodate!(rc : Int32, fn : String) : Nil
      return if rc == LibPkg::PkgErrorT::Ok.value || rc == LibPkg::PkgErrorT::UpToDate.value
      raise Error.from_pkg(rc, fn)
    end
  end
end
