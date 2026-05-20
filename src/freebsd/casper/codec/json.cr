require "json"

module FreeBSD::Casper
  module Codec
    # JSON codec for `Casper::Helper.spawn(codec: Casper::Codec::JSON)`.
    # Request and response types must include `JSON::Serializable`.
    module JSON
      def self.encode(value) : Bytes
        value.to_json.to_slice
      end

      def self.decode(bytes : Bytes, type : T.class) : T forall T
        T.from_json(String.new(bytes))
      end
    end
  end
end
