module FreeBSD::Audit
  # High-level API for writing BSM audit records.
  #
  # ```
  # FreeBSD::Audit::Event.write(FreeBSD::Audit::AUE::WebAuthFail) do |r|
  #   r.subject uid: 80_u32
  #   r.text "username=admin method=POST path=/admin"
  #   r.address "192.168.1.100"
  #   r.return_failure Errno::EACCES
  # end
  # ```
  module Event
    # Open an audit record, yield a `Record` builder, then commit the record.
    #
    # If the block raises, the record is discarded (`AU_TO_NO_WRITE`) and the
    # exception is re-raised. If the audit subsystem is not running,
    # `au_open(3)` returns -1 and `RecordOpenError` is raised before the block
    # is entered.
    #
    # Pass `strict: true` to raise `TokenWriteError` on any `au_write` failure
    # instead of silently counting it in `record.write_failures`.
    def self.write(event : AUE, strict : Bool = false, & : Record ->) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        d = LibBsm.au_open
        raise RecordOpenError.from_errno("au_open") if d == -1
        record = Record.new(d, strict)
        begin
          yield record
        rescue ex
          LibBsm.au_close(d, LibBsm::AU_TO_NO_WRITE, event.value)
          raise ex
        end
        LibBsm.au_close(d, LibBsm::AU_TO_WRITE, event.value)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Open an audit record, yield a `Record` builder, then **discard** it
    # without writing to the audit trail.
    #
    # Useful for testing token construction without a live auditd.
    def self.discard(event : AUE, & : Record ->) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        d = LibBsm.au_open
        raise RecordOpenError.from_errno("au_open") if d == -1
        record = Record.new(d, false)
        begin
          yield record
        rescue ex
          LibBsm.au_close(d, LibBsm::AU_TO_NO_WRITE, event.value)
          raise ex
        end
        LibBsm.au_close(d, LibBsm::AU_TO_NO_WRITE, event.value)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Open an audit record for an OCSF activity value, write the activity_id
    # token automatically, then commit the record.
    #
    # The *activity* argument must respond to `#aue : AUE` (which class owns
    # this activity) and `#value : UInt8` (the numeric activity ID). All
    # generated `Activity` enums satisfy this interface.
    #
    # ```
    # FreeBSD::Audit::Event.write_activity(FreeBSD::Audit::Authentication::Activity::Logon) do |r|
    #   r.subject uid: uid
    #   r.text "user=admin"
    #   r.address remote_ip
    #   r.return_failure
    # end
    # ```
    def self.write_activity(activity : T, strict : Bool = false, & : Record ->) : Nil forall T
      write(activity.aue, strict: strict) do |record|
        record.activity_id(activity.value, activity.to_s)
        yield record
      end
    end

    # Open an audit record for an OCSF activity value, write the activity_id
    # token automatically, then **discard** the record without writing to the
    # audit trail.
    #
    # Useful for testing activity token construction without a live auditd.
    def self.discard_activity(activity : T, & : Record ->) : Nil forall T
      discard(activity.aue) do |record|
        record.activity_id(activity.value, activity.to_s)
        yield record
      end
    end
  end
end
