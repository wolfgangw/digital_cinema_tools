#!/usr/bin/env ruby
#
# signature_check.rb examines signatures of DCinema documents
# Copyright 2012 Wolfgang Woehl
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
AppName = File.basename __FILE__
AppVersion = 'v0.2012.03.24'
#
# Usage:  signature_check.rb cpl.xml
#         signature_check.rb --quiet cpl.xml
#         signature_check.rb --help
#

require 'nokogiri'
require 'openssl'
require 'base64'
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse( args )
    # defaults
    options = OpenStruct.new
    options.verbose = TRUE

    opts = OptionParser.new do |opts|

      # Banner and usage
      opts.banner = <<BANNER
#{ AppName } #{ AppVersion }
Usage: #{ AppName } [-q, --quiet] <Signed XML file>
BANNER

      # Options
      opts.on( '-q', '--quiet', "Quiet operation. Exit codes 0 for verified signature and 1 for failure" ) do |p|
        options.verbose = FALSE
      end
      opts.on_tail( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
      end

    end
    begin
      opts.parse!( args )
    rescue Exception => e
      exit if e.class == SystemExit
      puts "Options error: #{ e.message }"
      exit
    end
    options
  end
end
options = Optparser.parse( ARGV )

class DC_Signature_Verification
  attr_reader :messages, :signature_node, :crypto, :reference_digests_check, :signature_value_check

  def initialize( doc )
    @messages = Array.new
    @signature_node = nil
    @crypto = nil
    @reference_digests_check = false
    @signature_value_check = false
    evaluation_complete = signature_verify( doc )
    report
  end

  def verified?
    @verified
  end

  def signer_name
    @crypto.context.first.subject.to_s
  end
  def signer_issuer
    @crypto.context.first.issuer.to_s
  end

  def report
    if @signature_node.size == 1
      case @reference_digests_check
      when TRUE
        @messages << "Document and SignedInfo match"
        case @signature_value_check
        when TRUE
          @messages << "Signature value and SignedInfo match"
        when FALSE
          @messages << "Signature value and SignedInfo do not match"
        end

      when FALSE
        @messages << "Document and SignedInfo do not match"
        case @signature_value_check
        when TRUE
          @messages << "Signature value and SignedInfo match"
        when FALSE
          @messages << "Signature value and SignedInfo do not match"
        end
      end

      if @reference_digests_check and @signature_value_check
        @verified = true
        @messages << "Signature check: OK"
      else
        @verified = false
        @messages << "Signature check: Verification failure"
      end
    end
  end

  def signature_namespace_and_prefix( doc )
    doc_ns = doc.collect_namespaces
    if doc_ns.key( MStr::Ns_Xmldsig )
      prefix = doc_ns.key( MStr::Ns_Xmldsig ).split( 'xmlns:' ).last
    else
      # If Signature's namespace is not in doc's namespace collection then it will be either
      #   * in Ns_Xmldsig declared as default namespace for Signature scope
      #   * or whacked beyond recognition
      prefix = 'xmlns'
    end
    sig_ns = { prefix => MStr::Ns_Xmldsig }
    return sig_ns, prefix
  end

  # Will return true/false for completing the evaluation
  # Actual verification results implied by @reference_digests_check and @signature_value_check
  def signature_verify( doc )
    # 1. Figure out signature namespace prefix
    sig_ns, prefix = signature_namespace_and_prefix( doc )

    # 2. Signature present?
    @signature_node = doc.xpath( "//#{ prefix }:Signature", sig_ns )
    if @signature_node.size != 1
      @messages << "#{ @signature_node.size == 0 ? 'No' : @signature_node.size } signature node#{ @signature_node.size > 1 ? 's' : '' } found"
      return FALSE
    end

    # 3. Extract and check signer certs
    certs = extract_certs( doc, sig_ns, prefix )
    @crypto = DC_Signer_Crypto_Compliance.new( certs )

    if ! @crypto.valid?
      if ! @crypto.errors[ :pre_context ].empty?
        @crypto.errors[ :pre_context ].each do |e|
          @messages << e
        end
        return FALSE
      else
        # Compliance issues in the extracted certs.
        # List those errors but then try to continue anyway,
        # thus allowing for inspection of compliance issues and signature in context.
        @crypto.messages.each do |e|
          @messages << e
        end
      end
    else # cc is valid
      @messages << "Certificate chain is complete and compliant (#{ @crypto.type })"
    end

    # 3.a Might check here whether the signer chain is known, trustworthy etc.
    #
    # See 3 for @crypto validity hop-over
    #

    # 4. Get signer's public key
    pub_k = @crypto.context.first.public_key

    # 5. Check references and signature value
    @reference_digests_check = check_references( doc, sig_ns, prefix )
    @signature_value_check = check_signature_value( doc, sig_ns, prefix, pub_k )

    return TRUE
  end # signature_verify

  def check_signature_value( doc, sig_ns, prefix, pub_k )
    sig_algo = doc_signature_method_algorithm( doc, sig_ns, prefix )
    sig_digest_algo = sig_algo.split( 'rsa-' ).last
    signature_value_doc = extract_signature_value( doc, sig_ns, prefix )
    if signature_value_doc.size != pub_k.n.to_i.size
      @messages << "Invalid signature: sig_doc: #{ signature_value_doc.size } octets (RSA modulus: #{ pub_k.n.to_i.size } octets)"
      return FALSE
    end
    signed_info_c14n_xml = signed_info_c14n( doc, sig_ns, prefix )

    signed_info_digest_calc = b64_enc( digest( sig_digest_algo, signed_info_c14n_xml ) )
    signed_info_digest_doc  = b64_enc( decode_sig_value( signature_value_doc, sig_digest_algo, pub_k ) )
    @messages << "SignedInfo Digest calc:    #{ signed_info_digest_calc } (SignatureMethod Algorithm=#{ sig_algo })"
    @messages << "SignedInfo Digest decoded: #{ signed_info_digest_doc  } (SignatureMethod Algorithm=#{ sig_algo })"

    return ( signed_info_digest_calc == signed_info_digest_doc )
  end

  def check_references( doc, sig_ns, prefix )
    check = TRUE
    references = doc_references( doc, sig_ns, prefix )
    check = FALSE if references.size == 0
    @messages << "Found #{ references.size } reference#{ references.size != 1 ? 's' : '' }"
    references.each do |ref|
      digest_algo = doc_reference_digest_method_algorithm( ref, sig_ns, prefix )
      digest_doc = doc_reference_digest_value( ref, sig_ns, prefix )
      if ref.attributes.size == 1 and ref.attributes[ 'URI' ]
        uri = ref.attributes[ 'URI' ].value
        case uri
        when ""
          ref_xml = strip_signature( doc.dup, sig_ns, prefix ).canonicalize
        else
          if uri =~ /^#ID_/
            ref_xml = extract_uri( doc, uri ).canonicalize
          else
            @messages << "Reference URI not valid"
            check = FALSE
            next
          end
        end
        digest_calc = b64_enc( digest( digest_algo, ref_xml ) )
        @messages << "URI=#{ uri.empty? ? '""' : uri } Digest calc: #{ digest_calc } (DigestMethod Algorithm=#{ digest_algo })"
        @messages << "URI=#{ uri.empty? ? '""' : uri } Digest doc:  #{ digest_doc  } (DigestMethod Algorithm=#{ digest_algo })"
        if digest_calc == digest_doc
          @messages << "Reference digest value correct"
        else
          @messages << "Reference digest value not correct"
          check = FALSE
        end
      else
        # not reached if doc was validated against schema
        @messages << "Reference has more than 1 attribute"
      end
    end
    return check
  end

  def attribute_value( element, attr_name )
    element.attributes[ attr_name ].text
  end

  def doc_signature_method_algorithm( doc, sig_ns, prefix )
    signature_method_algorithm( attribute_value( doc.at_xpath( "//#{ prefix }:SignatureMethod", sig_ns ), 'Algorithm' ) )
  end

  def doc_references( doc, sig_ns, prefix )
    doc.xpath( "//#{ prefix }:SignedInfo/#{ prefix }:Reference", sig_ns )
  end

  def doc_reference_digest_method_algorithm( reference, sig_ns, prefix )
    digest_method_algorithm( attribute_value( reference.at_xpath( "#{ prefix }:DigestMethod", sig_ns ), 'Algorithm' ) )
  end

  def doc_reference_digest_value( reference, sig_ns, prefix )
    reference.at_xpath( "#{ prefix }:DigestValue", sig_ns ).text
  end

  def signed_info_c14n( doc, sig_ns, prefix )
    doc.at_xpath( "//#{ prefix }:SignedInfo", sig_ns ).canonicalize
  end

  def digest( hash_id, m )
    OpenSSL::Digest.new( hash_id, m ).digest
  end

  def signature_method_algorithm( id )
    {
      'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => 'rsa-sha1',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'rsa-sha256'
    }[ id ]
  end

  def digest_method_algorithm( id )
    {
      'http://www.w3.org/2000/09/xmldsig#sha1' => 'sha1',
      'http://www.w3.org/2001/04/xmlenc#sha256' => 'sha256'
    }[ id ]
  end

  def emsa_pkcs1_v1_5_decode( hash_id, m )
    hash_size = digest( hash_id, '' ).size
    m[ m.size - hash_size, hash_size ]
  end

  # See rsa gem
  def os2ip( octet_string )
    octet_string.bytes.inject( 0 ) { |n, b| ( n << 8 ) + b }
  end

  # See rsa gem
  def i2osp( x, len = nil )
    raise ArgumentError, "integer too large" if len && x >= 256 ** len
    StringIO.open do |buffer|
      while x > 0
        b = ( x & 0xFF ).chr
        x >>= 8
        buffer << b
      end
      s = buffer.string
      s.force_encoding( Encoding::BINARY ) if s.respond_to?( :force_encoding )
      s.reverse!
      s = len ? s.rjust( len, "\0" ) : s
    end
  end

  # See rsa gem. note the bn modification here
  def modpow( base, exponent, modulus )
    result = 1
    while exponent > 0
      result = ( base * result ) % modulus unless ( ! exponent.bit_set? 0 )
      base = ( base * base ) % modulus
      exponent >>= 1
    end
    result
  end

  def rsavp1( pub_k, s )
    modpow( s, pub_k.e, pub_k.n )
  end

  def extract_certs( doc, sig_ns, prefix )
    certs = Array.new
    doc.xpath( "//#{ prefix }:X509Certificate", sig_ns ).each do |c|
      begin
        pem = pemify( c.text )
        certs << OpenSSL::X509::Certificate.new( pem )
      rescue Exception => e
        @messages << e.inspect
      end
    end
    certs
  end

  def pemify( string )
    [
      '-----BEGIN CERTIFICATE-----',
      string.gsub( /[\r ]+/, '' ).split( "\n" ).join.split( /(.{64})/ ).reject { |e| e.empty? },
      '-----END CERTIFICATE-----'
    ].flatten.join( "\n" )
  end

  def decode_sig_value( value, sig_digest_algo, pub_k )
    m = rsavp1( pub_k, os2ip( value ) )
    emsa_pkcs1_v1_5_decode( sig_digest_algo, i2osp( m, pub_k.n.to_i.size ) )
  end

  def strip_signature( doc, sig_ns, prefix )
    signature_element = doc.at_xpath( "//#{ prefix }:Signature", sig_ns )
    signature_element.remove
    doc
  end

  def extract_uri( doc, uri )
    # See kdms/kdm_19400_8a1ace55-3953-4a6a-9f74-becc1d42af69_97f83429b5258215db5f96e79c8cbb4c1f2c8c8d.xml,
    # a dolby KDM with prefixed children, like "etm:AuthenticatedPublic".
    # Iterating children to pick up uri because I don't know a simpler way for now
    requested_node_name = uri.split( '#ID_' ).last
    doc.root.children.each do |child|
      if child.node_name and child.node_name == requested_node_name
        prefix = child.namespace.prefix
        return doc.at_xpath( "//#{ prefix.nil? ? 'xmlns:' : prefix + ':' }#{ requested_node_name }[ @Id = '#{ uri[ 1 .. -1 ] }' ]" )
      end
    end
  end

  def b64_enc( octet_string )
    Base64.encode64( octet_string ).chomp
  end
  def b64_dec( string )
    Base64.decode64 string
  end

  def extract_signature_value( doc, sig_ns, prefix )
    b64_dec( doc.at_xpath( "//#{ prefix }:SignatureValue", sig_ns ).text.split( "\n" ).join )
  end

end # DC_Signature_Verification


class DC_Signer_Crypto_Compliance
  attr_reader :context, :errors, :crypto_context_valid, :type
  def initialize( certs )
    crypto_context( certs )
  end

  def crypto_context( certs )
    @errors = Hash.new
    @context, @errors[ :pre_context ] = find_crypto_context( certs )
    if @errors[ :pre_context ].empty?
      @errors[ :context ], @types_seen = check_compliance
      if @errors[ :pre_context ].empty? and @errors[ :context ].values.flatten.empty? and @chain_verified == TRUE
        if @types_seen.uniq.size == 1
          @type = @types_seen.first
          @crypto_context_valid = TRUE
        end
      else
        @crypto_context_valid = FALSE
      end
    else
      @crypto_context_valid = FALSE
    end
  end # crypto_context

  def valid?
    @crypto_context_valid
  end

  def messages
    e = Array.new
    @context.each do |cert|
      e << "Subject: #{ cert.subject.to_s }"
      e << "Issuer:  #{ cert.issuer.to_s }"
      unless @errors[ :context ].nil?
        if @errors[ :context ][ cert.subject.to_s ].empty?
          e << 'OK'
        else
          e << 'Not a compliant certificate:'
          @errors[ :context][ cert.subject.to_s ].each do |error|
            e << "\t" + error
          end
        end
      end
    end
    e << "Chain signatures #{ @chain_verified == TRUE ? 'verified' : 'verification failed' }"
    if total_errors == 0
      e << "Compliant certificate chain found: #{ @type } (#{ context.to_a.size } certificate#{ context.to_a.size != 1 ? 's' : '' }, 0 errors)"
    else
      e << "Not a compliant certificate chain: #{ context.to_a.size } certificate#{ context.to_a.size != 1 ? 's' : '' } with #{ total_errors } error#{ total_errors != 1 ? 's' : '' }"
    end
    return e
  end

  def find_crypto_context( pems )
    context = Array.new
    pre_context_errors = Array.new

    pems.each do |pem|
      begin
        cert_obj = OpenSSL::X509::Certificate.new( pem )
        context << cert_obj
      rescue
        # catch all exceptions (scan or CertificateError) and move on
      end
    end

    # Find root ca and collect issuers
    # ruby version of CTP's dsig_cert.py
    root = NIL
    issuer_map = Hash.new

    context.each do |cert|
      if cert.issuer.to_s == cert.subject.to_s
        if root
          pre_context_errors << "Multiple self-signed (root) certificates found"
          return [], pre_context_errors
        else
          root = cert
        end
      else
        issuer_map[ cert.issuer.to_s ] = cert
      end
    end
    if root == NIL
      pre_context_errors << "Self-signed root certificate not found"
      return [], pre_context_errors
    end

    # sort
    tmp_list = Array.new
    tmp_list << root
    begin
      key = tmp_list.last.subject.to_s
      child = issuer_map[ key ]
      while child
        tmp_list << child
        key = tmp_list.last.subject.to_s
        child = issuer_map[ key ]
      end
    rescue
      nil
    end # ruby version of CTP's dsig_cert.py

    if tmp_list.size == 1
      pre_context_errors << 'No issued certificates found'
      return context, pre_context_errors
    end

    if context.size != tmp_list.size
      pre_context_errors << 'Certificates do not form a complete chain'
      return context, pre_context_errors
    end
    # from here on 1st is leaf, 2nd .. n are intermediate ca's, last is self-signed root ca
    context = tmp_list.reverse
    return context, pre_context_errors
  end # find_crypto_context

  def check_compliance
    context_errors = Hash.new
    types_seen = Array.new
    @context.each_with_index do |member, index|
      cert = member
      type = NIL
      errors = Array.new
      errors << 'Not a X509 certificate' unless cert.is_a?( OpenSSL::X509::Certificate )
      # ctp sections:

      # 2.1.1 X.509 version 3
      errors << 'Not X509 version 3' unless cert.version == 2 # sic. versions 1 2 3 -> 0 1 2

      # 2.1.1 Issuer and subject present
      errors << 'Issuer missing' unless cert.issuer.is_a?( OpenSSL::X509::Name )
      errors << 'Subject missing' unless cert.subject.is_a?( OpenSSL::X509::Name )

      # * 2.1.2 Signature algorithm
      case cert.signature_algorithm
      when 'sha256WithRSAEncryption'
        type = :smpte
      when 'sha1WithRSAEncryption'
        type = :interop
      else
        errors << 'Signature algorithm not sha256WithRSAEncryption or sha1WithRSAEncryption'
      end

      # 2.1.3
      # Implicitly checked above

      # * 2.1.4 Serial number field non-negative integer less or equal to 64 or 160 bits respectively
      case type
      when :smpte
        errors << 'Serial number not in valid range' unless 0 <= cert.serial.to_i and cert.serial.to_i <= 2 ** 64
      when :interop
        errors << 'Serial number not in valid range' unless 0 <= cert.serial.to_i and cert.serial.to_i <= 2 ** 160
      else
        errors << 'Serial number not checked (Certificate type has not been established)'
      end

      # 2.1.5 SubjectPublicKeyInfo field modulus 2048 bit and e == 65537
      errors << 'Modulus not 2048 bits long' unless cert.public_key.n.to_i.size == 256 # 'n' is modulus (as OpenSSL::BN)
      errors << 'Public exponent not 65537' unless cert.public_key.e == 65537 # 'e' is public exponent (OpenSSL::BN)

      # 2.1.6 Deleted (in CTP 1.1) section

      # 2.1.7 Validity present (not before, not after)
      errors << 'Not before field missing' if cert.not_before.nil?
      errors << 'Not after field missing' if cert.not_after.nil?
      errors << 'Not before field is not UTC' unless cert.not_before.utc?
      errors << 'Not after field is not UTC' unless cert.not_after.utc?

      # Check X.509 extensions
      required_oids = %w( basicConstraints keyUsage authorityKeyIdentifier )
      additional_oids = Array.new

      cert.extensions.each do |x|
        if required_oids.include?( x.oid )
          required_oids.delete( x.oid )
          values = extension_values( x.value )

          case x.oid

          # 2.1.8 AuthorityKeyIdentifier field present
          when "authorityKeyIdentifier"
            nil # 2.1.8 checks for presence only. Omission in CTP?

          # 2.1.9 KeyUsage field
          when "keyUsage"
            if index == 0 # leaf cert
              errors << "digitalSignature missing from keyUsage" unless values.include?( 'Digital Signature' )
              errors << "keyEncipherment missing from keyUsage" unless values.include?( 'Key Encipherment' )
            else # ca's
              errors << "keyCertSign missing from keyUsage" unless values.include?( 'Certificate Sign' )
            end

          # * 2.1.10 basicConstraints field
          when "basicConstraints"
            if index == 0 # leaf cert
              errors << "CA true in potential #{ type } leaf certificate" unless values.include?( 'CA:FALSE' )
              case type
              when :smpte
                if values.find { |v| v.match( /pathlen:[^0]/ ) }
                  errors << "Pathlen present and non-zero in potential #{ type } leaf certificate"
                end
              when :interop
                if values.find { |v| v.match( /pathlen:[^0]/ ) }
                  errors << "Pathlen present and non-zero in potential #{ type } leaf certificate"
                end
              end
            else # ca's
              errors << 'basicConstraints not marked critical' unless x.critical?
              errors << 'CA false for authority certificate' unless values.include?( 'CA:TRUE' )
              if ! values.find { |v| v.match( /pathlen:\d+/ ) }
                # FIXME If the value in pathlen is negative the regexp above will not match
                # and thus trigger the error but the message will be misleading
                errors << 'Pathlen missing for authority certificate'
              end
            end
          end # case oid
        else
          additional_oids << x # see 2.1.15 checks
        end # required oid
      end # extensions
      errors << "Extensions #{ required_oids.join( ', ' ) } missing" unless required_oids.empty?

      # 2.1.11 Public key thumbprint dnQualifier
      #
      # This works for rubies < 1.9.3:
      #   asn1 = Base64.decode64( cert.public_key.to_pem.split( "\n" )[ 1 .. -2 ].join )
      #   dnq_calc = Base64.encode64( OpenSSL::Digest.new( 'sha1', asn1 ).digest ).chomp
      #
      # rubies >= 1.9.3 changed the default encoding of public key so do this instead:
      #
      pkey_der = OpenSSL::ASN1::Sequence( [ OpenSSL::ASN1::Integer( cert.public_key.n ), OpenSSL::ASN1::Integer( cert.public_key.e ) ] ).to_der
      dnq_calc = Base64.encode64( OpenSSL::Digest.new( 'sha1', pkey_der ).digest ).chomp
      #
      field_dnq = find_field( 'dnQualifier', cert.subject )
      if field_dnq.empty?
        errors << 'dnQualifier field missing in subject name'
      elsif field_dnq.size > 1
        errors << 'More than 1 dnQualifier field present'
      else
        dnq_cert = field_dnq.first[ 1 ]
        if dnq_cert.empty?
          errors << 'dnQualifier missing in subject name'
        end
        if dnq_calc != dnq_cert
          errors << "dnQualifier mismatch"
        end
      end

      # 2.1.12 OrganizationName field present in issuer and subject and identical
      field_o_issuer = find_field( 'O', cert.issuer )
      field_o_subject = find_field( 'O', cert.subject )
      if field_o_issuer.empty?
        errors << 'Organization name field missing in issuer name'
      elsif field_o_issuer.size > 1
        errors << 'More than 1 Organization name field present in issuer name'
      else
        o_issuer = field_o_issuer.first[ 1 ]
      end
      if field_o_subject.empty?
        errors << 'Organization name missing in subject name'
      elsif field_o_subject.size > 1
        errors << 'More than 1 Organization name field present in subject name'
      else
        o_subject = field_o_subject.first[ 1 ]
      end
      unless o_issuer.nil? and o_subject.nil?
        if o_issuer != o_subject
          errors << 'Organization name issuer/subject mismatch'
        end
      end

      # 2.1.13 OrganizationUnitName field
      field_ou_issuer = find_field( 'OU', cert.issuer )
      field_ou_subject = find_field( 'OU', cert.subject )
      if field_ou_issuer.empty?
        errors << 'OrganizationUnit field missing in issuer name'
      elsif field_ou_issuer.size > 1
        errors << 'More than 1 OrganizationUnit fields present in issuer name'
      else
        ou_issuer = field_ou_issuer.first[ 1 ]
      end
      if field_ou_subject.empty?
        errors << 'OrganizationUnit field missing in subject name'
      elsif field_ou_subject.size > 1
        errors << 'More than 1 OrganizationUnit fields present in subject name'
      else
        ou_subject = field_ou_subject.first[ 1 ]
      end
      if ou_issuer.nil?
        errors << 'OrganizationUnit name of issuer empty'
      end
      if ou_subject.nil?
        errors << 'OrganizationUnit name of subject empty'
      end

      # 2.1.14 Entity name and roles field
      field_cn_issuer = find_field( 'CN', cert.issuer )
      field_cn_subject = find_field( 'CN', cert.subject )
      if field_cn_issuer.empty?
        errors << 'CommonName field missing in issuer name'
      elsif field_cn_issuer.size > 1
        errors << 'More than 1 CommonName field present in issuer name'
      else
        cn_issuer = field_cn_issuer.first[ 1 ]
      end
      if field_cn_subject.empty?
        errors << 'CommonName field missing in subject name'
      elsif field_cn_subject.size > 1
        errors << 'More than 1 CommonName field present in subject name'
      else
        cn_subject = field_cn_subject.first[ 1 ]
        cn_subject_roles = cn_subject.split( /\..+/ )
        if cn_subject_roles.empty?
          roles = NIL
        else
          roles = cn_subject_roles.first.split( ' ' )
        end
      end

      if index == 0 # leaf
        case type
        when :smpte
          if cn_subject_roles.empty?
            errors << 'Role title missing in CommonName field of leaf certificate subject name'
          else
            errors << 'CS role missing in CommonName field of leaf certificate subject name' unless roles.include?( 'CS' )
            errors << 'Superfluous roles present in CommonName field of leaf certificate subject name' unless roles.size == 1 and roles[ 0 ] == 'CS'
          end
        when :interop
          # lax rules noop
        end
      else # ca's
        errors << 'Role title present in CommonName field of authority certificate' unless roles.nil?
      end

      # 2.1.15 unrecognized x509v3 extensions not marked critical
      additional_oids.each do |x|
        errors << 'Additional, non-required X.509v3 extension is marked critical' if x.critical?
      end

      context_errors[ cert.subject.to_s ] = errors
      types_seen << type
    end # @context.each

    # 2.1.16 signature verification. verify chain
    @chain_verified = verify_certs( @context )

    # 2.1.17 Chain complete? Validity period of child cert contained within validity of parent? Root ca valid?
    # The chain completeness and root ca checks are implicit in crypto_context() which leaves validity containment checks:
    @context.each_with_index do |cert, index|
      break if index == @context.size - 1 # root ca
      if ! ( cert.not_before >= @context[ index + 1 ].not_before and cert.not_after <= @context[ index + 1 ].not_after )
        context_errors[ cert.subject.to_s ] << "Validity period not contained within parent certificate's validity period"
      end
    end
    return context_errors, types_seen
  end # check_smpte_compliance

  # Verify a sorted certificate chain
  def verify_certs( certs )
    certs.each_with_index do |cert, index|
      if index == 0
        issuer = cert
      else
        issuer = certs[ index - 1 ]
      end
      begin
        cert.verify cert.public_key
      rescue Exception => e
        return FALSE
      end
    end
    return TRUE
  end

  def find_field( fieldname, x509_name )
    x509_name.to_a.find_all { |e| e.first.match '^' + fieldname + '$' }
  end

  def extension_values( string )
    string.split( ', ' )
  end

  def each
    @context.each {|f| yield( f ) }
  end

  def to_a
    @context.dup
  end

  def total_errors
    @errors[ :context ].values.flatten.size
  end
end # DC_Signer_Crypto_Compliance


module MStr
  Ns_Xmldsig  = 'http://www.w3.org/2000/09/xmldsig#'
end # module MStr


def check_signature( xml )
  signature_result = DC_Signature_Verification.new( xml )
end

def get_xml( file )
  begin
    xml = Nokogiri::XML( open file )
  rescue Exception => e
    puts "#{ file }: #{ e.message }"
    return FALSE
  end
  unless xml.errors.empty?
    xml.errors.each do |e|
      puts "Syntax error: #{ file }: #{ e }"
    end
    return FALSE
  end
  return xml
end


if ARGV.size != 1
  puts "Usage: #{ File.basename __FILE__ } <XML file>"
  exit
else
  file = ARGV[ 0 ]
end


# Nokogiri git master (2012.01.11) implements interface to libxml2's C14N
if Nokogiri::XML::Document.new.respond_to?( 'canonicalize' )
  c14n_available = TRUE
  xml = get_xml( ARGV[ 0 ] )
else
  puts "Installed version of Nokogiri does not support C14N which is required for signature verification"
  puts "See https://github.com/wolfgangw/digital_cinema_tools/wiki/MISC for notes on how to install Nokogiri with C14N support from current git (https://github.com/tenderlove/nokogiri)"
  c14n_available = FALSE
end

if c14n_available and xml
  signature_result = check_signature( xml )
  puts signature_result.messages if options.verbose
end

if signature_result.verified?
  exit 0
else
  exit 1
end

