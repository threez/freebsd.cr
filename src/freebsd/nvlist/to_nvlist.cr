# Encoding support for primitive and collection types.
#
# Each type gains a `#to_nvlist(builder, key)` method so that
# `FreeBSD::NVList::Builder#field` can dispatch generically.

struct Nil
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.null(key)
  end
end

struct Bool
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.bool(key, self)
  end
end

struct Int8
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct Int16
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct Int32
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct Int64
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct UInt8
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct UInt16
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct UInt32
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, to_u64)
  end
end

struct UInt64
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.number(key, self)
  end
end

class String
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.string(key, self)
  end
end

struct Slice(T)
  # Only Bytes (Slice(UInt8)) is meaningful as binary; other slices encode
  # as nested nvlists with index keys.
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    {% if T == UInt8 %}
      builder.binary(key, self)
    {% else %}
      builder.nvlist(key) do |child|
        each_with_index { |v, i| child.field(i.to_s, v) }
      end
    {% end %}
  end
end

class Array(T)
  # Encodes as a nested nvlist with string-form integer keys "0", "1", …
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.nvlist(key) do |child|
      each_with_index { |v, i| child.field(i.to_s, v) }
    end
  end
end

class Hash(K, V)
  # Keys must be `String`. Encodes as a nested nvlist.
  def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
    builder.nvlist(key) do |child|
      each { |k, v| child.field(k.to_s, v) }
    end
  end
end
