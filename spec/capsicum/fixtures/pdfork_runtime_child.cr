# Fixture for the "pdfork child that starts the Crystal runtime" regression.
#
# A pdfork child that calls `previous_def` brings up its own Crystal runtime
# (full __crystal_main). This used to SIGSEGV because pdfork ran
# `Process.after_fork_child_callbacks` in the child pre-runtime, and the first
# callback (`Crystal::EventLoop.current.after_fork`) crashes before the runtime
# exists. The spec compiles and runs this program and asserts the child does
# not dump core.
#
# Prints "child-ran" from the child and "parent-ran" from the parent, then the
# parent reaps the child and exits 0.

require "../../../src/freebsd/casper"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  def Crystal.main_user_code(argc : Int32, argv : UInt8**)
    pd = FreeBSD::Capsicum.pdfork do
      previous_def # start the runtime in the child — the crashy path
      STDOUT.puts "child-ran"
      STDOUT.flush
      0
    end
    previous_def # start the runtime in the parent
    pd.wait
    pd.close
  end
{% end %}

STDOUT.puts "parent-ran"
