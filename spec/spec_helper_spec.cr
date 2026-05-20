require "./spec_helper"

# Portable tests of `in_sandbox_child` itself — exercise the fork + pipe
# protocol without needing Capsicum. The real sandboxing specs rely on this
# helper, so a failure here is a leading indicator.
describe "in_sandbox_child" do
  it "returns normally on a passing child" do
    in_sandbox_child { 1.should eq(1) }
  end

  it "surfaces a child assertion failure with the child's backtrace" do
    ex = expect_raises(Exception, /sandbox child failed.*expected: 2/im) do
      in_sandbox_child { 1.should eq(2) }
    end
    ex.message.try(&.includes?("Spec::AssertionFailed")).should be_true
  end

  it "surfaces an unhandled child exception" do
    expect_raises(Exception, /sandbox child failed.*boom/im) do
      in_sandbox_child { raise "boom from child" }
    end
  end

  it "runs before_wait while the child is alive" do
    parent_ran = false
    in_sandbox_child(before_wait: -> {
      parent_ran = true
      nil
    }) do
      sleep 20.milliseconds # give the parent time to run before_wait before we exit
    end
    parent_ran.should be_true
  end

  it "propagates a parent-side exception from before_wait" do
    expect_raises(Exception, /parent oops/) do
      in_sandbox_child(before_wait: -> { raise "parent oops" }) { sleep 10.milliseconds }
    end
  end
end
