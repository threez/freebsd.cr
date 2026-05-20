require "../spec_helper"
require "../../src/freebsd/nvlist"

record NVPoint, x : Int32, y : Int32 do
  include FreeBSD::NVList::Serializable
end

record NVInner, label : String do
  include FreeBSD::NVList::Serializable
end

record NVOuter, name : String, inner : NVInner do
  include FreeBSD::NVList::Serializable
end

record NVRenamed, x : Int32 do
  include FreeBSD::NVList::Serializable

  @[FreeBSD::NVList::Field(key: "x_coord")]
  @x : Int32
end

record NVWithIgnored, keep : String, skip : String do
  include FreeBSD::NVList::Serializable

  @[FreeBSD::NVList::Field(ignore: true)]
  @skip : String
end

describe FreeBSD::NVList::Serializable do
  it_on_capsicum "encodes a struct to nvlist and decodes it back" do
    pt = NVPoint.new(x: 3, y: 4)
    builder = FreeBSD::NVList::Builder.new
    pt.to_nvlist(builder, "pt")
    pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
    decoded = NVPoint.new(pull.read_nvlist("pt"))
    decoded.x.should eq(3)
    decoded.y.should eq(4)
  end

  it_on_capsicum "supports nested serializable structs" do
    outer = NVOuter.new(name: "test", inner: NVInner.new(label: "hi"))
    builder = FreeBSD::NVList::Builder.new
    outer.to_nvlist(builder, "o")
    pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
    decoded = NVOuter.new(pull.read_nvlist("o"))
    decoded.name.should eq("test")
    decoded.inner.label.should eq("hi")
  end

  it_on_capsicum "honours FreeBSD::NVList::Field(key:) rename" do
    r = NVRenamed.new(x: 99)
    builder = FreeBSD::NVList::Builder.new
    r.to_nvlist(builder, "r")
    pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
    inner = pull.read_nvlist("r")
    inner.read_number("x_coord").should eq(99_u64)
    NVRenamed.new(inner).x.should eq(99)
  end

  it_on_capsicum "honours FreeBSD::NVList::Field(ignore: true)" do
    w = NVWithIgnored.new(keep: "kept", skip: "skipped")
    builder = FreeBSD::NVList::Builder.new
    w.to_nvlist(builder, "w")
    pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)
    inner = pull.read_nvlist("w")
    inner.exists?("keep").should be_true
    inner.exists?("skip").should be_false
  end
end
