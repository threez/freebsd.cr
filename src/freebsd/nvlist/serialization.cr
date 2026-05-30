module FreeBSD::NVList
  # Per-field annotation, mirroring `JSON::Field`.
  #
  # Options:
  # * **key** — override the nvlist key name (default: instance variable name)
  # * **ignore** — skip this field in both directions (default: false)
  # * **ignore_serialize** — skip during encoding only
  # * **ignore_deserialize** — skip during decoding only
  # * **converter** — module/class with `to_nvlist(value, builder, key)` and
  #   `from_nvlist(pull, key) : T` class methods
  annotation Field
  end

  # Include `FreeBSD::NVList::Serializable` to auto-generate `#to_nvlist`,
  # `#to_nvlist_fields`, `self.from_nvlist`, and a constructor from a
  # `FreeBSD::NVList::PullParser`. Mirrors `JSON::Serializable`.
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
  #
  # Nested serializable structs are fully supported:
  #
  # ```
  # record Inner, z : String do
  #   include FreeBSD::NVList::Serializable
  # end
  # record Outer, name : String, inner : Inner do
  #   include FreeBSD::NVList::Serializable
  # end
  # ```
  module Serializable
    macro included
      # Decode from a PullParser (at a nested nvlist level).
      def self.from_nvlist(pull : ::FreeBSD::NVList::PullParser) : self
        new(pull)
      end

      # Constructor from a PullParser pointing at a nested nvlist.
      def initialize(pull : ::FreeBSD::NVList::PullParser)
        {% verbatim do %}
          {% begin %}
            {% for ivar in @type.instance_vars %}
              {% ann = ivar.annotation(::FreeBSD::NVList::Field) %}
              {% unless ann && (ann[:ignore] || ann[:ignore_deserialize]) %}
                {% key = ((ann && ann[:key]) || ivar.name).id.stringify %}
                {% ivar_type = ivar.type %}
                {% if ann && ann[:converter] %}
                  @{{ ivar.name }} = {{ ann[:converter] }}.from_nvlist(pull, {{ key }})
                {% elsif ivar_type <= Bool %}
                  @{{ ivar.name }} = pull.read_bool({{ key }})
                {% elsif ivar_type <= Bool? %}
                  @{{ ivar.name }} = pull.read_bool?({{ key }})
                {% elsif ivar_type <= UInt64 %}
                  @{{ ivar.name }} = pull.read_number({{ key }})
                {% elsif ivar_type <= UInt64? %}
                  @{{ ivar.name }} = pull.read_number?({{ key }})
                {% elsif ivar_type <= Int8 || ivar_type <= Int16 || ivar_type <= Int32 || ivar_type <= Int64 ||
                           ivar_type <= UInt8 || ivar_type <= UInt16 || ivar_type <= UInt32 %}
                  @{{ ivar.name }} = {{ ivar_type }}.new(pull.read_number({{ key }}))
                {% elsif ivar_type <= String %}
                  @{{ ivar.name }} = pull.read_string({{ key }})
                {% elsif ivar_type <= String? %}
                  @{{ ivar.name }} = pull.read_string?({{ key }})
                {% elsif ivar_type <= Bytes %}
                  @{{ ivar.name }} = pull.read_binary({{ key }})
                {% elsif ivar_type <= Bytes? %}
                  @{{ ivar.name }} = pull.read_binary?({{ key }})
                {% elsif ivar_type.nilable? %}
                  {% non_nil = ivar_type.union_types.reject { |type| type == Nil }.first %}
                  nested_pull = pull.read_nvlist?({{ key }})
                  @{{ ivar.name }} = nested_pull ? {{ non_nil }}.new(nested_pull) : nil
                {% else %}
                  @{{ ivar.name }} = {{ ivar_type }}.new(pull.read_nvlist({{ key }}))
                {% end %}
              {% end %}
            {% end %}
          {% end %}
        {% end %}
      end

      # Encode all fields directly into *builder* (no extra nesting).
      def to_nvlist_fields(builder : ::FreeBSD::NVList::Builder) : Nil
        {% verbatim do %}
          {% begin %}
            {% for ivar in @type.instance_vars %}
              {% ann = ivar.annotation(::FreeBSD::NVList::Field) %}
              {% unless ann && (ann[:ignore] || ann[:ignore_serialize]) %}
                {% key = ((ann && ann[:key]) || ivar.name).id.stringify %}
                {% if ann && ann[:converter] %}
                  {{ ann[:converter] }}.to_nvlist(@{{ ivar.name }}, builder, {{ key }})
                {% else %}
                  builder.field({{ key }}, @{{ ivar.name }})
                {% end %}
              {% end %}
            {% end %}
          {% end %}
        {% end %}
      end

      # Encode self into *builder* under *key* as a nested nvlist.
      def to_nvlist(builder : ::FreeBSD::NVList::Builder, key : String) : Nil
        builder.nvlist(key) { |child| to_nvlist_fields(child) }
      end
    end
  end
end
