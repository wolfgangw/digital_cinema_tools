#!/usr/bin/env ruby
#
#
# dc_crypto_context.rb checks X509 certificates for SMPTE 430-2 compliance
# Copyright 2011 Wolfgang Woehl
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
AppVersion = 'v0.2011.04.09'
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

class DC_Crypto_Context
  attr_reader :context, :errors, :chain_verified, :crypto_context_valid
  CHAINFILE_FOUND = 'Concatenated chain found and used. Please split'
  def initialize( files )
    crypto_context_find( files )
  end
  
  def crypto_context_find( files )
    @errors = Hash.new
    @context, @errors[ :pre_context ] = crypto_context( files )
    if @errors[ :pre_context ].empty? or ( @errors[ :pre_context ].size == 1 and @errors[ :pre_context ][0] == CHAINFILE_FOUND )
      @errors[ :context ] = check_smpte_compliance
      if @errors[ :pre_context ].empty? and @errors[ :context ].values.flatten.empty? and @chain_verified == TRUE
        @crypto_context_valid = TRUE
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
          # alternatively we could
          # pre_context_errors << CHAINFILE_FOUND 
          # parts = raw.scan( /-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m )
          # parts.each do |part|
          #   context << { :x509 => OpenSSL::X509::Certificate.new( part ), :cert_file => File.expand_path( file ) }
          # end
        else
          # Brute-force try and rescue here, not exactly elegant
          cert_obj = OpenSSL::X509::Certificate.new( raw )
          context << { :x509 => cert_obj, :cert_file => File.expand_path( file ) }
        end
      rescue OpenSSL::X509::CertificateError => e
        # move on (e.message)
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
  
  
  def check_smpte_compliance
    context_errors = Hash.new
    @context.each_with_index do |member, index|
      errors = Array.new
      cert = member[ :x509 ]
      cert_file = member[ :cert_file ]
      errors << 'Not a X509 certificate' unless cert.is_a?( OpenSSL::X509::Certificate )
      
      # ctp sections:
      
      # 2.1.1 X.509 version 3
      errors << 'Not X509 version 3' unless cert.version == 2 # sic. versions 1 2 3 -> 0 1 2
      
      # 2.1.1 Issuer and subject present
      errors << 'Issuer missing' unless cert.issuer.is_a?( OpenSSL::X509::Name )
      errors << 'Subject missing' unless cert.subject.is_a?( OpenSSL::X509::Name )
      
      # 2.1.2 Signature algorithm "sha256WithRSAEncryption"
      errors << 'Signature algorithm not sha256WithRSAEncryption' unless cert.signature_algorithm == 'sha256WithRSAEncryption'
      
      # 2.1.3 Verify that the SignatureValue field is present outside the signed part of the certificate and contains an ASN.1 Bit String that contains a PKCS #1 SHA256WithRSA signature block.
      # FIXME
      # How to test 2.1.3 other than looking at openssl's text output?
      
      # 2.1.4 Serial number field non-negative integer less or equal to 8 bytes
      errors << 'Serial number not in valid range' unless 0 <= cert.serial.to_i and cert.serial.to_i <= 256 ** 8
      
      # 2.1.5 SubjectPublicKeyInfo field modulus 2048 bit and e == 65537
      errors << 'Modulus not 2048 bits long' unless cert.public_key.n.to_i.size == 256 # 'n' is modulus (as OpenSSL::BN)
      errors << 'Public exponent not 65537' unless cert.public_key.e == 256 ** 2 + 1 # 'e' is public exponent (OpenSSL::BN)
      
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
              if values.find { |v| v.match( /pathlen:[^0]/ ) }
                errors << 'Pathlen present and non-zero for leaf certificate'
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
      dnq_calc= `openssl x509 -pubkey -noout -in #{ cert_file } | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64`.chomp
      # equiv. dnq_calc = `echo #{ cert.public_key.to_pem } | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64`.chomp
      # equiv. dnq_calc = Base64.encode64( OpenSSL::Digest::SHA1.digest( Base64.decode64( cert.public_key.to_pem )[24..-1] ) ).chomp
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
      
      # Digital cinema compliant X509 names need O, OU, CN and dnQualifier fields:
      #   subject=/O=example.org/OU=csc.example.org/CN=.dcstore.smpte-430-2.INTERMEDIATE/dnQualifier=Ep6g9AZrooGTteMGVylJ2g1P8Es=
      # ruby's openssl bindings provide OpenSSL::X509::Name which is used here in the form of arrays:
      #   certificate.subject.to_a
      #     [["O", "example.org", 19], ["OU", "csc.example.org", 19], ["CN", ".dcstore.smpte-430-2.INTERMEDIATE", 19], ["dnQualifier", "Ep6g9AZrooGTteMGVylJ2g1P8Es=", 19]]
      
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
      
      if index == 0 # leaf certificate
        if cn_subject_roles.empty?
          errors << 'Role title missing in CommonName field of leaf certificate subject name'
        else
          errors << 'CS role missing in CommonName field of leaf certificate subject name' unless roles.include?( 'CS' )
        end
      else # ca's
        errors << 'Role title present in CommonName field of authority certificate' unless roles.nil?
      end
      # I _think_ role checks can be omitted for issuer name because they will always be present and their subject names will get checked
      
      # 2.1.15 unrecognized x509v3 extensions not marked critical
      additional_oids.each do |x|
        errors << 'Additional, non-required X.509v3 extension is marked critical' if x.critical?
      end
          
      context_errors[ member[ :cert_file ] ] = errors
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
    # A leaf certificate's validity period is supposed to be completely contained within its signer certificate's validity period.
    # This is a recursive requirement, down to the chain's penultimate authority certificate, which is in turn constrained by 
    # the self-signed root authority's validity period.
    # While the specs are explicit wrt the "not after" boundary (child's "not after" must precede parent's "not after") 
    # that explicitness is missing for the "not before" boundary. In other words, it is not specified whether validity periods 
    # beginning at the exact same time are valid.
    @context.each_with_index do |member, index|
      break if index == @context.size - 1 # root ca
      if ! ( member[ :x509 ].not_before >= @context[ index + 1 ][ :x509 ].not_before and member[ :x509 ].not_after < @context[ index + 1 ][ :x509 ].not_after )
        context_errors[ member[ :cert_file ] ] << "Validity period not contained within parent certificate's validity period"
      end
    end
    return context_errors
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
    @context.each do |member|
      puts "Certificate file: #{ member[ :cert_file ] }", "Subject: #{ OpenSSL::X509::Certificate.new( File.read( member[ :cert_file ] ) ).subject.to_s }", "Issuer:  #{ OpenSSL::X509::Certificate.new( File.read( member[ :cert_file ] ) ).issuer.to_s }"
      unless @errors[ :context ].nil?
        if @errors[ :context ][ member[ :cert_file ] ].empty?
          puts 'OK'
        else
          puts 'Not a SMPTE compliant certificate:'
          puts "\t" + @errors[ :context ][ member[ :cert_file ] ].join( "\n\t" )
        end
      end
    end
    if total_errors == 0
      puts "SMPTE compliant certificate chain found: #{ context.to_a.size } certificates, 0 errors"
    else
      puts "No SMPTE compliant certificate chain found: #{ context.to_a.size } certificates with #{ total_errors } errors"
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
    exit
  end
else
  puts "Usage: #{ File.basename( $0 ) } <directory>"
  exit
end

cc = DC_Crypto_Context.new( files )

if cc.valid?
  puts cc.messages
else
  if ! cc.errors[ :pre_context ].empty?
    puts cc.errors[ :pre_context ]
  else
    puts cc.messages
  end
end

