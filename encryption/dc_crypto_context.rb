#!/usr/bin/env ruby
#
# dc_crypto_context.rb checks X509 certificates for SMPTE 430-2 compliance
#
# Usage: dc_crypto_context.rb <dir>
#
# 2011-2012 Wolfgang Woehl
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
AppVersion = 'v0.2012.04.08'
#
# Script will check a given set of files for the presence of a SMPTE compliant certificate chain, used in 
# digital cinema to sign Composition Playlists (CPL), Packing Lists (PKL) and Key Delivery Messages (KDM).
# Script runs all the compliance checks listed in CTP v1.1, chapter 2 (http://www.dcimovies.com/DCI_CTP_v1_1.pdf)
# to make sure the certificates meet all digital cinema/SMPTE specific requirements.
#
# DC_Crypto_Context will try to pick (from a set of files) a SMPTE compliant certificate chain and return
#   * a list of "pre-context" errors (triggered when trying to find certificates in the first place)
#   * a list of smpte compliance "context" errors (triggered in the compliance tests)
#   * a list of certificates with some related properties:
#     1st is leaf certificate with :cert_file, :x509 (as OpenSSL::X509::Certificate) and :rsa_key_file
#     <2nd .. n> are intermediate CA's with :cert_file and :x509
#     last is self-signed root CA with :cert_file and :x509
#
#   context = [
#     { :rsa_key_file => <path>, :cert_file => <path>, :x509 => <pem string> },
#     { :cert_file => <path>, :x509 => <pem string> },
#     ...,
#     { :cert_file => <path>, :x509 => <pem string> }
#   ]
#   errors = {
#     :pre_context => [ <list of error messages> ],
#     :context => {
#       <cert_file_1> => [ <list of error messages> ],
#       <cert_file_2> => [ <list of error messages> ],
#       ...
#     }
#   }
#   chain_verified = true|false
#   crypto_context_valid = true|false
#
# Using context.x509 extensively in the compliance checks. After those checks context.x509 (OpenSSL::X509::Certificate)
# is useless and will be dropped when the context is registered.
#
require 'openssl'
require 'base64'

class DC_Crypto_Context
  attr_reader :context, :errors, :chain_verified, :crypto_context_valid, :type
  CHAINFILE_FOUND = 'Concatenated chain found and used. Please split'
  def initialize( files )
    crypto_context_find( files )
  end

  def crypto_context_find( files )
    @errors = Hash.new
    @context, @errors[ :pre_context ] = crypto_context( files )
    if @errors[ :pre_context ].empty? or ( @errors[ :pre_context ].size == 1 and @errors[ :pre_context ][0] == CHAINFILE_FOUND )
      @errors[ :context ], @types_seen = check_compliance
      if @errors[ :pre_context ].empty? and @errors[ :context ].values.flatten.empty? and @chain_verified == TRUE
        if @types_seen.uniq.size == 1
          @type = @types_seen.first
          @crypto_context_valid = TRUE
        else
          @type = 'Mixed'
          @crypto_context_valid = FALSE
        end
      else
        @crypto_context_valid = FALSE
      end
    else
      @crypto_context_valid = FALSE
    end
  end # crypto_context_find

  def crypto_context( files )
    context = Array.new
    pre_context_errors = Array.new

    files.each do |file|
      next unless File.ftype( file ) == 'file'
      raw = File.read( file )
      begin
        if raw.scan( /-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m ).size > 1 # could be concatenated chain, could also be this file :)
          # ignore chain file candidates for now
          next
        else
          cert_obj = OpenSSL::X509::Certificate.new( raw )
          context << { :x509 => cert_obj, :cert_file => File.expand_path( file ) }
        end
      rescue
        # catch all (scan or Certificate) and move on
      end
    end

    # Find root ca and collect issuers in order to be able to sort the chain.
    # (Basically a ruby version of CTP's dsig_cert.py)
    root = NIL
    issuer_map = Hash.new

    context.each do |cert|
      if cert[ :x509 ].issuer.to_s == cert[ :x509 ].subject.to_s
        # self-signed
        if root
          pre_context_errors << "Multiple self-signed (root) certificates found"
          return [], pre_context_errors
        else
          root = cert
        end
      else
        # intermediate or leaf
        issuer_map[ cert[ :x509 ].issuer.to_s ] = cert
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
      key = tmp_list.last[ :x509 ].subject.to_s
      child = issuer_map[ key ]
      while child
        tmp_list << child
        key = tmp_list.last[ :x509 ].subject.to_s
        child = issuer_map[ key ] # leaf has not issued a certificate
      end
    rescue
      nil
    end # ruby version of CTP's dsig_cert.py

    if tmp_list.size == 1
      pre_context_errors << 'No issued certificates found'
      return context, pre_context_errors
    else
      # Find leaf's private key
      leaf_public_key = tmp_list.last[ :x509 ].public_key.inspect
      files.each do |file|
        next unless File.ftype( file ) == 'file'
        begin
          # Again, brute-force try and rescue
          rsa_key = OpenSSL::PKey::RSA.new( File.read( file ) )
          # equiv. check_private_key( key )
          if leaf_public_key == rsa_key.public_key.inspect
            tmp_list.last[ :rsa_key_file ] = file
          end
        rescue OpenSSL::PKey::RSAError => e
          # move on (e.message)
        end
      end
      if tmp_list.last[ :rsa_key_file ] == NIL
        pre_context_errors << "Leaf certificate's private key not found"
      end
    end

    if context.size != tmp_list.size
      pre_context_errors << 'Certificates do not form a complete chain'
      return context, pre_context_errors
    end
    # from here on 1st is leaf, 2nd .. n are intermediate ca's, last is self-signed root ca
    context = tmp_list.reverse
    return context, pre_context_errors
  end # crypto_context


  def check_compliance
    context_errors = Hash.new
    types_seen = Array.new
    @context.each_with_index do |member, index|
      errors = Array.new
      cert = member[ :x509 ]
      type = NIL
      cert_file = member[ :cert_file ]
      errors << 'Not a X509 certificate' unless cert.is_a?( OpenSSL::X509::Certificate )

      # ctp sections:

      # 2.1.1 X.509 version 3
      errors << 'Not X509 version 3' unless cert.version == 2 # sic. versions 1 2 3 -> 0 1 2

      # 2.1.1 Issuer and subject present
      errors << 'Issuer missing' unless cert.issuer.is_a?( OpenSSL::X509::Name )
      errors << 'Subject missing' unless cert.subject.is_a?( OpenSSL::X509::Name )

      # 2.1.2 Signature algorithm "sha256WithRSAEncryption"
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

      # 2.1.4 Serial number field non-negative integer less or equal to 8 bytes
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
      #
      # Note on Ruby version 1.8.7:
      #
      # UTC time > jan 19th 2038 is broken in ruby 1.8.7 on 32 bit systems (See https://bugs.ruby-lang.org/issues/5885)
      # See {"o"=>"DC256.Cinea.Com"} {"ou"=>"Root-CA.DC256.Cinea.Com"} {"cn"=>".Cinea.Root-CA.0"} {"dnq"=>"NFkBZDCGa7KpLK0PhZNCt40dDi8="} {"not_before"=>2006-05-12 16:08:58 UTC} {"not_after"=>2041-05-01 00:00:00 UTC} for a valid X509 cert exceeding 32 bit time_t.
      # See COFD-3D_FTR-8_C_EN-XX_US_51_2K_20110308_DLB_i3D for a package with NFkBZDCGa7KpLK0PhZNCt40dDi8=.
      # See DC_Signer_Crypto_Compliance Section 2.1.17 for another spot where this matters.
      #
      begin
        errors << 'Not before field missing' if cert.not_before.nil?
        errors << 'Not after field missing' if cert.not_after.nil?
        errors << 'Not before field is not UTC' unless cert.not_before.utc?
        errors << 'Not after field is not UTC' unless cert.not_after.utc?
      rescue Exception => e
        errors << "Internal error: Skip DC_Signer_Crypto_Compliance Section 2.1.7 Validity: RUBY_VERSION #{ RUBY_VERSION } on 32 bit systems broken for UTC times > Jan 19th 2038. Inspect certificate manually." if e.class == ArgumentError
      end

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
            nil # 2.1.8 checks for presence only. Would that be an inadvertent omission in CTP?

          # 2.1.9 KeyUsage field
          when "keyUsage"
            if index == 0 # leaf cert
              errors << "digitalSignature missing from keyUsage" unless values.include?( 'Digital Signature' )
              errors << "keyEncipherment missing from keyUsage" unless values.include?( 'Key Encipherment' )
            else # ca's
              errors << "keyCertSign missing from keyUsage" unless values.include?( 'Certificate Sign' )
            end

          # 2.1.10 basicConstraints field
          when "basicConstraints"
            if index == 0 # leaf cert
              # FIXME these break with additional items in value which should be ignored instead
              errors << 'CA true for leaf certificate' unless values.include?( 'CA:FALSE' )
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

      context_errors[ member[ :cert_file ] ] = errors
      types_seen << type
    end # @context.each

    # 2.1.16 signature verification. verify chain
    # OpenSSL::X509::StoreContext could be used here. Segfaults, though, on ruby 1.8.7 (2010-01-10 patchlevel 249) [i486-linux], had a problem on 1.9, too.
    x509_store = OpenSSL::X509::Store.new
    @context.each_with_index do |member, index|
      next if index == 0
      x509_store.add_cert( member[ :x509 ] )
    end
    x509_store.verify( @context.first[ :x509 ] )
    if x509_store.error != 0
      @chain_verified = FALSE
    else
      @chain_verified = TRUE
    end

    # 2.1.17 Chain complete? Validity period of child cert contained within validity of parent? Root ca valid?
    # The chain completeness and root ca checks are implicit in crypto_context() which leaves validity containment checks:
    @context.each_with_index do |cert, index|
      break if index == @context.size - 1 # root ca
      begin
        if ! ( cert.not_before >= @context[ index + 1 ].not_before and cert.not_after <= @context[ index + 1 ].not_after )
          context_errors[ cert.subject.to_s ] << "Validity period not contained within parent certificate's validity period"
        end
      rescue Exception => e
        context_errors[ cert.subject.to_s ] << "Internal error: Skip DC_Signer_Crypto_Compliance Section 2.1.17 Chain completeness: RUBY_VERSION #{ RUBY_VERSION } on 32 bit systems broken for UTC times > Jan 19th 2038. Inspect certificate manually." if e.class == ArgumentError
      end
    end

    return context_errors, types_seen
  end # smpte_compliant?

  def find_field( fieldname, x509_name )
    x509_name.to_a.find_all { |e| e.first.match '^' + fieldname + '$' }
  end

  def extension_values( string )
    string.split( ', ' )
  end

  def each
    @context.each {|f| yield(f) }
  end

  def to_a
    @context.dup
  end

  def total_errors
    @errors[ :context ].values.flatten.size
  end

  def valid?
    @crypto_context_valid
  end

  def messages
    @context.each_with_index do |member, index|
      puts "Certificate file: #{ member[ :cert_file ] }", "Subject: #{ OpenSSL::X509::Certificate.new( File.read( member[ :cert_file ] ) ).subject.to_s }", "Issuer:  #{ OpenSSL::X509::Certificate.new( File.read( member[ :cert_file ] ) ).issuer.to_s }"
      unless @errors[ :context ].nil?
        if @errors[ :context ][ member[ :cert_file ] ].empty?
          puts 'OK'
        else
          puts "Not a #{ @types_seen[ index ] } compliant certificate:"
          @errors[ :context ][ member[ :cert_file ] ].each do |error|
            puts "\t" + error
          end
        end
      end
    end
    if total_errors == 0
      puts "Compliant certificate chain found: #{ @type } (#{ @context.to_a.size } certificates, 0 errors)"
    else
      puts "Not a compliant certificate chain: #{ @context.to_a.size } certificate#{ @context.to_a.size != 1 ? 's' : '' } with #{ total_errors } error#{ total_errors != 1 ? 's' : '' }"
    end
    puts "Chain signatures #{ @chain_verified == TRUE ? 'verified' : 'verification failed' }"
  end

end # DCSignatureContext


# Example usage:
# $ dc_crypto_context.rb <dir>
if ARGV.size == 1
  dir = ARGV[ 0 ]
  if File.exists?( dir ) and File.ftype( dir ) == 'directory'
    files = Dir.glob( File.join( dir, '*' ) )
  else
    puts "Not found: #{ dir }"
    exit 1
  end
else
  puts "Usage: #{ File.basename( $0 ) } <directory>"
  exit 1
end

cc = DC_Crypto_Context.new( files )

if cc.valid?
  puts cc.messages
  exit 0
else
  if ! cc.errors[ :pre_context ].empty?
    puts cc.errors[ :pre_context ]
    exit 1
  else
    puts cc.messages
    exit 1
  end
end

