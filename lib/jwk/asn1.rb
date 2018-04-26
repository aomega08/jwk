module JWK
  class ASN1
    class << self
      def rsa_public_key(n, e)
        pubkey = bit_string(sequence(integer(n), integer(e)).to_der)
        sequence(rsa_header, pubkey).to_der
      end

      def rsa_private_key(*args)
        raise ArgumentError('Some pieces missing for RSA Private Key') unless args.length == 8
        sequence(integer(0), *args.map { |n| integer(n) }).to_der
      end

      def ec_private_key(crv, d, raw_public_key)
        object_id = object_id_for_crv(crv).to_der

        sequence(
          integer(1),
          integer_octet_string(d),
          context_specific(true, 0, object_id),
          context_specific(true, 1, bit_string(raw_public_key).to_der)
        ).to_der
      end

      private

      def object_id_for_crv(crv)
        id = case crv
             when 'P-256'
               '1.2.840.10045.3.1.7'
             when 'P-384'
               '1.3.132.0.34'
             when 'P-521'
               '1.3.132.0.35'
             end

        object_id(id)
      end

      def object_id(id)
        OpenSSL::ASN1::ObjectId.new(id)
      end

      def null
        OpenSSL::ASN1::Null.new(nil)
      end

      def rsa_header
        sequence(
          object_id('1.2.840.113549.1.1.1'),
          null
        )
      end

      def bit_string(data)
        OpenSSL::ASN1::BitString.new(data)
      end

      def sequence(*items)
        OpenSSL::ASN1::Sequence.new(items)
      end

      def integer(n)
        OpenSSL::ASN1::Integer.new(n)
      end

      def integer_octet_string(n)
        _, data = raw_integer_encoding(n)
        OpenSSL::ASN1::OctetString.new(data)
      end

      def asn_length(n)
        if n > 127
          self_len, data = raw_integer_encoding(n)
          self_len |= 0x80
          self_len.chr + data
        else
          n.chr
        end
      end

      def raw_integer_encoding(n)
        # find out how many octets are required to encode it
        num_octets = (n.to_s(16).length / 2.0).ceil

        # encode the low num_octets bytes of the integer.
        shifted = n << 8
        data = Array.new(num_octets) do
          ((shifted >>= 8) & 0xFF).chr
        end.join.reverse

        [num_octets, data]
      end

      def context_specific(structured, tag, content)
        tag |= 0x80
        tag |= 0x20 if structured

        tag.chr + asn_length(content.length) + content.force_encoding('ASCII-8BIT')
      end
    end
  end
end
