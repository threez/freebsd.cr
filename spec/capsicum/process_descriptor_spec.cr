require "../spec_helper"

describe FreeBSD::Capsicum::ProcessDescriptor do
  it_on_capsicum "pdfork returns a usable descriptor for a short-lived child" do
    pd = FreeBSD::Capsicum.pdfork do
      sleep 50.milliseconds
      0
    end

    pd.fd.should be > 0
    pd.pid.should be > 0
    pd.current_pid.should eq(pd.pid)

    pd.close
    pd.closed?.should be_true
  end

  it_on_capsicum "pdkill terminates the child" do
    pd = FreeBSD::Capsicum.pdfork do
      sleep 5.seconds
      0
    end
    # SIGKILL is unblockable — using it makes the test independent of how
    # Crystal's child handles SIGTERM in its event loop.
    pd.kill(Signal::KILL)
    status = pd.wait(1.second)
    status.should_not be_nil
    pd.close
  end

  it_on_capsicum "wait returns the child's Process::Status" do
    pd = FreeBSD::Capsicum.pdfork do
      sleep 20.milliseconds
      42
    end
    status = pd.wait
    status.should_not be_nil
    status.try(&.exit_code).should eq(42)
    pd.close
  end

  it_on_capsicum "wait honors a timeout and leaves the child running" do
    pd = FreeBSD::Capsicum.pdfork do
      sleep 5.seconds
      0
    end
    pd.wait(50.milliseconds).should be_nil
    pd.current_pid.should_not be_nil
    pd.close
  end

  it_on_capsicum "wait works from inside capability mode" do
    in_sandbox_child do
      pd = FreeBSD::Capsicum.pdfork do
        sleep 20.milliseconds
        7
      end
      FreeBSD::Capsicum.sandbox!
      status = pd.wait
      status.try(&.exit_code).should eq(7)
    end
  end

  it_on_capsicum "child exception is caught — pd close completes cleanly" do
    pd = FreeBSD::Capsicum.pdfork { raise "boom" }
    pd.fd.should be > 0
    pd.close
  end
end
