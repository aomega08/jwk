module JWK
  class Key
    EC_KTY = 'EC'.freeze
    RSA_KTY = 'RSA'.freeze
    OCT_KTY = 'oct'.freeze
    VALID_KTY = [EC_KTY, RSA_KTY, OCT_KTY].freeze

    class << self
      def from_pem(pem)
        key = OpenSSL::PKey.read(pem)
        if defined?(OpenSSL::PKey::EC) && key.is_a?(OpenSSL::PKey::EC)
          $stderr.puts('WARNING: EC Keys have bugs on jRuby') if defined?(JRUBY_VERSION)
        end
        from_openssl(key)
      end

      def from_openssl(key)
        if key.is_a?(OpenSSL::PKey::RSA)
          RSAKey.from_openssl(key)
        elsif key.is_a?(OpenSSL::PKey::EC) || key.is_a?(OpenSSL::PKey::EC::Point)
          ECKey.from_openssl(key)
        end
      end

      def from_json(json)
        key = JSON.parse(json)
        from_hash(key)
      end

      def from_hash(hash)
        key = stringify_keys(hash)
        validate_kty!(key['kty'])

        case key['kty']
        when 'EC'
          ECKey.new(key)
        when 'RSA'
          RSAKey.new(key)
        when 'oct'
          OctKey.new(key)
        end
      end

      def validate_kty!(kty)
        unless VALID_KTY.include?(kty)
          raise JWK::InvalidKey, "The provided JWK has an unknown \"kty\" value: #{kty}."
        end
      end

      private

      def stringify_keys(h)
        hash = {}
        h.each do |key, value|
          value = value.stringify_keys if value.is_a?(Hash)
          hash[key.to_s] = value
          hash
        end
        hash
      end
    end

    def to_json
      @key.to_json
    end

    %w[kty use key_ops alg kid x5u x5c x5t].each do |part|
      define_method(part) do
        @key[part]
      end
    end

    def x5t_s256
      @key['x5t#S256']
    end

    protected

    def pem_base64(content)
      Base64.strict_encode64(content).scan(/.{1,64}/).join("\n")
    end

    def generate_pem(header, asn)
      "-----BEGIN #{header} KEY-----\n" +
        pem_base64(asn) +
        "\n-----END #{header} KEY-----\n"
    end
  end
end
