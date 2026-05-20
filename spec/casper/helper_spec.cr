require "../spec_helper"
require "../../src/freebsd/nvlist"

# Typed helper calculator protocol — request/response types for the
# typed dispatch spec. All use FreeBSD::NVList::Serializable to match
# the default FreeBSD::Casper::Codec::NVList.

record CalcAdd, a : Int32, b : Int32 do
  include FreeBSD::NVList::Serializable
end

record CalcMul, a : Int32, b : Int32 do
  include FreeBSD::NVList::Serializable
end

record CalcDiv, a : Int32, b : Int32 do
  include FreeBSD::NVList::Serializable
end

record CalcResult, value : Int32 do
  include FreeBSD::NVList::Serializable
end

record TypedPing do
  include FreeBSD::NVList::Serializable
end

record TypedPong do
  include FreeBSD::NVList::Serializable
end

# `FreeBSD::Casper::Helper.spawn` forks a helper (server) process; the calling process
# becomes the client. Specs that sandbox themselves must still run inside
# `in_sandbox_child` to keep the one-way `cap_enter` from rendering the spec
# runner unusable after the test finishes.

describe FreeBSD::Casper::Helper do
  it "round-trips request/reply between forked helper and calling client" do
    in_sandbox_child do
      client = FreeBSD::Casper::Helper.spawn do |server|
        server.serve do |op, payload|
          case op
          when "echo"  then payload
          when "upper" then String.new(payload).upcase.to_slice
          else              raise "unknown op: #{op}"
          end
        end
      end

      begin
        String.new(client.request("echo", "hi".to_slice)).should eq("hi")
        String.new(client.request("upper", "hello".to_slice)).should eq("HELLO")
      ensure
        client.close
      end
    end
  end

  it "surfaces helper exceptions as RemoteError in the caller" do
    in_sandbox_child do
      client = FreeBSD::Casper::Helper.spawn do |server|
        server.serve do |op, _payload|
          raise "boom from helper" if op == "fail"
          "ok".to_slice
        end
      end

      begin
        expect_raises(FreeBSD::Casper::Helper::RemoteError, /boom/) do
          client.request("fail")
        end
        String.new(client.request("ping")).should eq("ok")
      ensure
        client.close
      end
    end
  end

  it "serve loop exits cleanly when the client closes its end" do
    in_sandbox_child do
      client = FreeBSD::Casper::Helper.spawn do |server|
        server.serve { |_op, payload| payload }
      end
      String.new(client.request("ping", "x".to_slice)).should eq("x")
      client.close
    end
  end

  it "typed dispatch: named calculator helper handles multiple op types" do
    in_sandbox_child do
      client = FreeBSD::Casper::Helper.spawn(name: "calc") do |server|
        server.on(CalcAdd) { |r| CalcResult.new(value: r.a + r.b) }
        server.on(CalcMul) { |r| CalcResult.new(value: r.a * r.b) }
        server.on(CalcDiv) { |r|
          raise ArgumentError.new("division by zero") if r.b == 0
          CalcResult.new(value: r.a // r.b)
        }
        server.serve_typed
      end
      begin
        client.name.should eq("calc")
        client.request(CalcAdd.new(a: 3, b: 4), CalcResult).value.should eq(7)
        client.request(CalcMul.new(a: 6, b: 7), CalcResult).value.should eq(42)
        client.request(CalcDiv.new(a: 10, b: 3), CalcResult).value.should eq(3)
        expect_raises(FreeBSD::Casper::Helper::RemoteError, /division by zero/) do
          client.request(CalcDiv.new(a: 1, b: 0), CalcResult)
        end
      ensure
        client.close
      end
    end
  end

  it "unknown op surfaces as RemoteError in typed dispatch" do
    in_sandbox_child do
      client = FreeBSD::Casper::Helper.spawn do |server|
        server.on(TypedPing) { |_| TypedPong.new }
        server.serve_typed
      end
      begin
        expect_raises(FreeBSD::Casper::Helper::RemoteError, /unknown op/) do
          client.request("not_registered", Bytes.empty)
        end
      ensure
        client.close
      end
    end
  end
end
