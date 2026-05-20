require "../spec_helper"
require "../../src/freebsd/nvlist"

describe FreeBSD::NVList::PullParser do
  it_on_capsicum "optional readers return nil for absent keys" do
    builder = FreeBSD::NVList::Builder.new
    builder.string("x", "y")
    pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)

    pull.read_string?("x").should eq("y")
    pull.read_string?("nope").should be_nil
    pull.read_bool?("nope").should be_nil
    pull.read_number?("nope").should be_nil
    pull.read_binary?("nope").should be_nil
    pull.read_nvlist?("nope").should be_nil
  end

  it_on_capsicum "raises KeyError for missing required keys" do
    builder = FreeBSD::NVList::Builder.new
    pull = FreeBSD::NVList::PullParser.new(builder.to_unsafe)

    expect_raises(KeyError) { pull.read_string("missing") }
    expect_raises(KeyError) { pull.read_bool("missing") }
    expect_raises(KeyError) { pull.read_number("missing") }
    expect_raises(KeyError) { pull.read_binary("missing") }
    expect_raises(KeyError) { pull.read_nvlist("missing") }
  end
end
