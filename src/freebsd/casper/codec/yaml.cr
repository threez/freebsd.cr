require "yaml"

module FreeBSD::Casper
  module Codec
    # YAML codec for `Casper::Helper.spawn(codec: Casper::Codec::YAML)`.
    # Request and response types must include `YAML::Serializable`.
    module YAML
      def self.encode(value) : Bytes
        value.to_yaml.to_slice
      end

      def self.decode(bytes : Bytes, type : T.class) : T forall T
        T.from_yaml(String.new(bytes))
      end
    end
  end
end
