#!/usr/bin/env ruby
#
# decrypt_kdm.rb decrypts Interop/SMPTE KDM
#
# Wolfgang Woehl 2011-2024
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
AppName = File.basename( __FILE__ )
AppVersion = 'v0.2024.01.12'
#
if RUBY_VERSION <= '1.9'
  begin
    require 'rubygems'
  rescue LoadError
  end
end
require 'openssl'
require 'base64'
require 'nokogiri'
require 'pp'
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse( args )
    # defaults
    options = OpenStruct.new
    options.output_as_keyid_keytype_keydata_triple = false

    opts = OptionParser.new do |opts|

      # Banner and usage
      opts.banner = <<BANNER
#{ AppName } #{ AppVersion }
Usage: #{ AppName } [options] <KDM file> <RSA private key file>
BANNER

      # Options
      opts.on( '--as-triple', "Output content keys as <key id>:<key type>:<key data> triple to STDOUT" ) do |p|
        options.output_as_keyid_keytype_keydata_triple = true
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
      exit 1
    end
    options
  end
end
options = Optparser.parse( ARGV )


def exit_usage
  puts "Usage: #{ AppName } [options] <KDM file> <RSA private key file>"
  return exit
end

class KDMCipher
  attr_reader :plaintext, :type
  def initialize( cipher_b64, pkey )
    @plaintext = Hash.new
    begin
      decrypted_blob = pkey.private_decrypt( Base64.decode64( cipher_b64 ), OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING )
    rescue Exception => e
      puts "#{ e.inspect }. Wrong RSA private key?"
      return nil
    end

    case decrypted_blob.size
    when 134
      @type = :interop
      template = [
        [:structure_id,       16],
        [:signer_thumbprint,  20],
        [:cpl_id,             16],
        [:key_id,             16],
        [:not_valid_before,   25],
        [:not_valid_after,    25],
        [:key_data,           16]
      ]
    when 138
      @type = :smpte
      template = [
        [:structure_id,       16],
        [:signer_thumbprint,  20],
        [:cpl_id,             16],
        [:key_type,            4],
        [:key_id,             16],
        [:not_valid_before,   25],
        [:not_valid_after,    25],
        [:key_data,           16]
      ]
    else
      raise "#{ decrypted_blob.size } bytes: KDMCipher plaintext package size does not match Interop or SMPTE specs"
    end

    pos = 0
    template.each.map do |field, length|
      blob = decrypted_blob[ pos .. pos + length - 1 ]
      @plaintext[ field ] = self.send( field, blob )
      pos += length
    end
  end

  def structure_id( blob )      blob.unpack( 'H2' * 16 ).join         end
  def signer_thumbprint( blob ) Base64::encode64( blob ).chomp        end
  def cpl_id( blob )            to_uuid_rep blob.unpack( 'H*' ).first end
  def key_type( blob )          blob                                  end
  def key_id( blob )            to_uuid_rep blob.unpack( 'H*' ).first end
  def not_valid_before( blob )  blob                                  end
  def not_valid_after( blob )   blob                                  end
  def key_data( blob )          blob.unpack( 'H2' * 16 ).join         end

  def to_uuid_rep( h )
    [ h[ 0 .. 7 ], h[ 8 .. 11 ], h[ 12 .. 15 ], h[ 16 .. 19 ], h[ 20 .. 31 ] ].join( '-' )
  end
end

types = {
  :smpte => KDM_SMPTE = "http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type",
  :interop => KDM_INTEROP = "http://www.digicine.com/PROTO-ASDCP-KDM-20040311#"
}

#
if ARGV.size != 2
  exit_usage
else
  begin
    xml = Nokogiri::XML( open ARGV[ 0 ] )
    pkey = OpenSSL::PKey::RSA.new( File.open ARGV[ 1 ] )
  rescue Exception => e
    puts e.inspect
    exit_usage
  end
end

message = 'DCinemaSecurityMessage'
# either this or, rather, schema check
# root.node_name will be nil for non-xml
if xml.root.node_name != message
  puts 'Not a DCinemaSecurityMessage'
  exit_usage
else
  xml.remove_namespaces!
  message_id = xml.xpath( "//#{ message }/AuthenticatedPublic/MessageId" ).text.split( 'urn:uuid:' ).last
  message_type = xml.xpath( "//#{ message }/AuthenticatedPublic/MessageType" ).text
  cipher_values = xml.xpath( "//#{ message }/AuthenticatedPrivate/EncryptedKey/CipherData/CipherValue" )
  case message_type
  when types[ :smpte ]
    type = :smpte
  when types[ :interop ]
    type = :interop
  end
  kdm_info = "#{ type } KDM: #{ message } #{ message_id } (#{ message_type })"
  if options.output_as_keyid_keytype_keydata_triple
    $stderr.puts kdm_info
  else
    puts kdm_info
  end

  kc = nil
  cipher_values.each do |cvn|
    cv = cvn.text
    kc = KDMCipher.new( cv, pkey )
    if kc
      if options.output_as_keyid_keytype_keydata_triple
        puts "#{ kc.plaintext[ :key_id ] }:#{ kc.plaintext[ :key_type ] }:#{ kc.plaintext[ :key_data ] }"
      else
        pp kc
      end
    else
      next
    end
  end
  exit_usage unless kc
end

