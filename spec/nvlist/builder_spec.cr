require "../spec_helper"
require "../../src/freebsd/nvlist"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  private def round_trip(& : FreeBSD::NVList::Builder ->) : FreeBSD::NVList::PullParser
    builder = FreeBSD::NVList::Builder.new
    yield builder
    FreeBSD::NVList::PullParser.new(builder.to_unsafe)
  end
{% end %}

describe FreeBSD::NVList::Builder do
  it_on_capsicum "round-trips a bool" do
    pull = round_trip(&.bool("flag", true))
    pull.read_bool("flag").should be_true
  end

  it_on_capsicum "round-trips a number (UInt64)" do
    pull = round_trip(&.number("n", 42_u64))
    pull.read_number("n").should eq(42_u64)
  end

  it_on_capsicum "round-trips a string" do
    pull = round_trip(&.string("s", "hello"))
    pull.read_string("s").should eq("hello")
  end

  it_on_capsicum "round-trips binary (Bytes)" do
    data = Bytes[1, 2, 3]
    pull = round_trip(&.binary("bin", data))
    pull.read_binary("bin").should eq(data)
  end

  it_on_capsicum "round-trips a nested nvlist" do
    pull = round_trip do |b|
      b.nvlist("inner") do |child|
        child.string("name", "nested")
      end
    end
    inner = pull.read_nvlist("inner")
    inner.read_string("name").should eq("nested")
  end

  it_on_capsicum "null key is detectable via exists?" do
    pull = round_trip(&.null("gone"))
    pull.exists?("gone").should be_true
    pull.exists?("missing").should be_false
  end

  it_on_capsicum "field dispatches Int32 as number" do
    pull = round_trip(&.field("v", 7))
    pull.read_number("v").should eq(7_u64)
  end

  it_on_capsicum "field dispatches String" do
    pull = round_trip(&.field("k", "val"))
    pull.read_string("k").should eq("val")
  end
end
