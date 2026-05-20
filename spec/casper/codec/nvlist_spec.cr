require "../../spec_helper"
require "../../../src/freebsd/casper/codec/nvlist"

record CodecPoint, x : Int32, y : Int32 do
  include FreeBSD::NVList::Serializable
end

describe FreeBSD::Casper::Codec::NVList do
  it_on_capsicum "round-trips a struct through encode/decode" do
    pt = CodecPoint.new(x: 10, y: 20)
    bytes = FreeBSD::Casper::Codec::NVList.encode(pt)
    decoded = FreeBSD::Casper::Codec::NVList.decode(bytes, CodecPoint)
    decoded.x.should eq(10)
    decoded.y.should eq(20)
  end

  it_on_capsicum "encode produces non-empty bytes" do
    bytes = FreeBSD::Casper::Codec::NVList.encode(CodecPoint.new(x: 1, y: 2))
    bytes.size.should be > 0
  end
end
