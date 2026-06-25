# Entry point for FreeBSD Capsicum bindings (sys/capsicum.h + pdfork).
#
# Loads: capability mode, fd rights, and process descriptors.
# Does NOT load libcasper or any casper services.
#
# ```
# require "freebsd/capsicum"
#
# rights = FreeBSD::Capsicum::Capability::Rights.new(
#   FreeBSD::Capsicum::Capability::Right::Read,
#   FreeBSD::Capsicum::Capability::Right::Fstat,
# )
# rights.apply_to(file)
#
# pd = FreeBSD::Capsicum.pdfork { run_untrusted_code; 0 }
# FreeBSD::Capsicum.sandbox!
# pd.wait
# ```
module FreeBSD::Capsicum
  # True when running on a platform that supports Capsicum.
  SUPPORTED = {{ flag?(:freebsd) || flag?(:dragonfly) }}

  # :nodoc:
  # Cooperative blocking-syscall wrapper. On Crystal 1.20+ uses
  # `Fiber.syscall` so other fibers can run while the call blocks; on older
  # Crystals just invokes the block directly (other fibers pause until the
  # syscall returns).
  def self.syscall(&)
    {% if compare_versions(Crystal::VERSION, "1.20.0") >= 0 %}
      ::Fiber.syscall { yield }
    {% else %}
      yield
    {% end %}
  end
end

require "./capsicum/errors"
require "./capsicum/lib_capsicum"
require "./capsicum/lib_pdfork"
require "./capsicum/capability"
require "./capsicum/directory"
require "./capsicum/process_descriptor"
