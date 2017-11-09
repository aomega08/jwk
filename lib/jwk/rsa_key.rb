require 'jwk/key'

module JWK
  class RSAKey < Key
    def initialize(key)
      @key = key
      validate
    end

    def public?
      true
    end

    def private?
      !@key['d'].nil?
    end

    def validate
      raise JWK::InvalidKey, 'Invalid RSA key.' unless @key['n'] && @key['e']
    end

    def to_pem
      asn = to_asn

      if private?
        generate_pem('RSA PRIVATE', asn)
      else
        generate_pem('PUBLIC', asn)
      end
    end

    def to_openssl_key
      OpenSSL::PKey.read(to_pem)
    end

    def to_s
      to_pem
    end

    %w[n e d p q dp dq qi].each do |part|
      define_method(part) do
        decode_base64_int(@key[part]) if @key[part]
      end
    end

    private

    def to_asn
      if private?
        unless full_private?
          raise NotImplementedError, 'Cannot convert RSA private key to PEM. Missing key data.'
        end

        ASN1.rsa_private_key(*key_parts)
      elsif public?
        ASN1.rsa_public_key(n, e)
      end
    end

    def full_private?
      @key['d'] && @key['p'] && @key['q'] && @key['dp'] && @key['dq'] && @key['qi']
    end

    def key_parts
      [n, e, d, p, q, dp, dq, qi]
    end
  end
end