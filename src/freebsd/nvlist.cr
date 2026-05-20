# FreeBSD nvlist — named-value list encoder/decoder.
#
# Mirrors Crystal's `JSON` module interface:
# - `FreeBSD::NVList::Builder`      — build (encode) an nvlist
# - `FreeBSD::NVList::PullParser`   — read (decode) an nvlist
# - `FreeBSD::NVList::Serializable` — opt-in macro for structs and classes
#
# Each service must be explicitly required:
#
# ```
# require "freebsd/nvlist"
#
# record Point, x : Int32, y : Int32 do
#   include FreeBSD::NVList::Serializable
# end
#
# builder = FreeBSD::NVList::Builder.new
# Point.new(x: 3, y: 4).to_nvlist(builder, "pt")
# pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
# pt = Point.new(pull.read_nvlist("pt"))
# pt.x # => 3
# ```
module FreeBSD::NVList
  # Raised when an nvlist operation is attempted on an unsupported platform.
  class UnsupportedPlatformError < RuntimeError
    def initialize
      super("FreeBSD::NVList requires FreeBSD or DragonFlyBSD")
    end
  end
end

require "./nvlist/lib_nv"
require "./nvlist/builder"
require "./nvlist/pull_parser"
require "./nvlist/to_nvlist"
require "./nvlist/serialization"
