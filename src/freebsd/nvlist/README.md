# FreeBSD::NVList

Crystal bindings for **libnv** — FreeBSD's named-value list library, used
internally by libcasper and the kernel for structured data exchange.

```crystal
require "freebsd/nvlist"
```

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises
> `FreeBSD::NVList::UnsupportedPlatformError`.

## Builder

`FreeBSD::NVList::Builder` writes typed key/value pairs into a native nvlist.

```crystal
builder = FreeBSD::NVList::Builder.new

builder.bool("flag", true)
builder.number("count", 42_u64)
builder.string("name", "hello")
builder.binary("blob", Bytes[1, 2, 3])
builder.null("gone")

# Nested nvlist — the block receives a child Builder
builder.nvlist("inner") do |child|
  child.string("nested", "value")
end

ptr = builder.to_unsafe   # => LibNv::Nvlist* (passed to C APIs or PullParser)
```

`builder.field(key, value)` dispatches to the correct typed method based on
the Crystal type of `value` — convenient when writing generic serialization:

```crystal
builder.field("x", 7_i32)      # => number (UInt64)
builder.field("s", "hello")    # => string
builder.field("ok", true)      # => bool
```

Supported types for `field`: `Nil`, `Bool`, `Int8`–`Int64`, `UInt8`–`UInt64`,
`String`, `Slice(UInt8)`, and any type that implements `to_nvlist`.

## PullParser

`FreeBSD::NVList::PullParser` reads typed values from a `LibNv::Nvlist*` pointer.

```crystal
pull = FreeBSD::NVList::PullParser.new(ptr)

pull.read_bool("flag")        # => Bool
pull.read_number("count")     # => UInt64
pull.read_string("name")      # => String
pull.read_binary("blob")      # => Bytes
pull.exists?("key")           # => Bool (true even for null entries)

inner = pull.read_nvlist("inner")   # => PullParser for the nested list
inner.read_string("nested")         # => "value"
```

## Round-trip example

```crystal
require "freebsd/nvlist"

builder = FreeBSD::NVList::Builder.new
builder.number("x", 10_u64)
builder.string("label", "origin")

pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
pull.read_number("x")      # => 10_u64
pull.read_string("label")  # => "origin"
```

## Serializable macro

Include `FreeBSD::NVList::Serializable` in any struct or record to get automatic
`to_nvlist` serialization and nvlist-backed initialization:

```crystal
require "freebsd/nvlist"

record Point, x : Int32, y : Int32 do
  include FreeBSD::NVList::Serializable
end

# Encode
builder = FreeBSD::NVList::Builder.new
pt = Point.new(x: 3, y: 4)
pt.to_nvlist(builder, "pt")

# Decode
pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
decoded = Point.new(pull.read_nvlist("pt"))
decoded.x   # => 3
decoded.y   # => 4
```

Nested serializable structs work automatically — each nested struct is stored
as a child nvlist under its field name:

```crystal
record Inner, label : String do
  include FreeBSD::NVList::Serializable
end

record Outer, name : String, inner : Inner do
  include FreeBSD::NVList::Serializable
end

builder = FreeBSD::NVList::Builder.new
Outer.new(name: "test", inner: Inner.new(label: "hi")).to_nvlist(builder, "o")

pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
obj  = Outer.new(pull.read_nvlist("o"))
obj.inner.label   # => "hi"
```

## Field annotation

Use `@[FreeBSD::NVList::Field(...)]` on instance variables to control
serialization behaviour:

**Rename a field** — store under a different key in the nvlist:

```crystal
record Renamed, x : Int32 do
  include FreeBSD::NVList::Serializable

  @[FreeBSD::NVList::Field(key: "x_coord")]
  @x : Int32
end

# The nvlist will contain "x_coord", not "x"
```

**Ignore a field** — omit it from serialization entirely:

```crystal
record WithSecret, public_val : String, secret : String do
  include FreeBSD::NVList::Serializable

  @[FreeBSD::NVList::Field(ignore: true)]
  @secret : String
end

# "secret" is never written to or read from the nvlist
```
