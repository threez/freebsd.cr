require "socket"

module FreeBSD::Audit
  # Shared convenience overloads for record-building objects.
  #
  # Included by both `FreeBSD::Audit::Record` and
  # `FreeBSD::Casper::AuditHelper::TokenBuffer`. Concrete classes implement the
  # primitive `text(String)`, `address(String)`, and `return_failure(UInt32)`
  # methods; this module adds the ergonomic overloads on top.
  module AuditRecordBuilder
    # Append a text token built from key=value pairs.
    #
    # ```
    # r.text(user: "admin", method: "POST", path: "/login")
    # # writes token: "user=admin method=POST path=/login"
    # ```
    def text(**fields) : Nil
      text(fields.map { |k, v| "#{k}=#{v}" }.join(' '))
    end

    # Append a remote-address token for a structured socket address.
    # The port component is ignored; only the IP is recorded.
    #
    # ```
    # r.address(Socket::IPAddress.new("192.168.1.1", 443))
    # ```
    def address(addr : Socket::IPAddress) : Nil
      address(addr.address)
    end

    # Append a failure return token for a well-typed `Errno` constant.
    #
    # ```
    # r.return_failure(Errno::EACCES)
    # ```
    def return_failure(error : Errno) : Nil
      return_failure(error.value.to_u32)
    end

    # Append an OCSF activity_id text token.
    # Format: `activity_id=N activity=Name`
    #
    # Called automatically by `Event.write_activity` — rarely needed directly.
    def activity_id(id : UInt8, name : String) : Nil
      text("activity_id=#{id} activity=#{name}")
    end

    # Append an OCSF activity_id token from a typed Activity enum value.
    # *activity* must respond to `#value : UInt8` and `#to_s` — all generated
    # `Activity` enums satisfy this interface.
    #
    # ```
    # r.activity_id(FreeBSD::Audit::Authentication::Activity::Logon)
    # # equivalent to: r.activity_id(1_u8, "Logon")
    # ```
    def activity_id(activity : T) : Nil forall T
      activity_id(activity.value, activity.to_s)
    end
  end
end
