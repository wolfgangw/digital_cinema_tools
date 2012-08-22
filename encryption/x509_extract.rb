#!/usr/bin/env ruby
#
# x509_extract.rb extracts X509 certificates from signed DCinema documents
#
# Wolfgang Woehl 2012
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
AppVersion = 'v0.2012.02.12'
#
# Usage:  x509_extract.rb path/to/signed.xml
#         x509_extract.rb --help
#
# Requirements
#   - Nokogiri
#

if RUBY_VERSION <= '1.9'
  begin
    require 'rubygems'
  rescue LoadError => e
    raise e.message
  end
end
require 'nokogiri'
require 'openssl'
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse( args )
    # defaults
    options = OpenStruct.new
    options.prefix = 'chain'
    options.quiet = FALSE

    opts = OptionParser.new do |opts|
      # Banner and usage
      opts.banner = <<BANNER
#{ AppName } #{ AppVersion }
Usage: #{ AppName } [-p, --prefix <Signed XML file>]
BANNER

      # Options
      opts.on( '-p', '--prefix prefix', String, 'Prefix for extracted pems' ) do |p|
        options.prefix = p
      end
      opts.on( '-q', '--quiet', 'No verbose output (Use exit codes 0 or 1)' ) do
        options.quiet = TRUE
      end
      opts.on_tail( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit 0
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

def extract_certs( doc, sig_ns, prefix )
  certs = Array.new
  doc.xpath( "//#{ prefix }:X509Certificate", sig_ns ).each do |c|
    begin
      pem = pemify( c.text )
      certs << OpenSSL::X509::Certificate.new( pem )
    rescue Exception => e
      puts e.inspect
    end
  end
  certs
end

def sort_certs( certs )
  # Find root ca and collect issuers
  # ruby version of CTP's dsig_cert.py
  root = NIL
  issuer_map = Hash.new
  errors = Array.new

  certs.each do |cert|
    if cert.issuer.to_s == cert.subject.to_s
      if root
        errors << "Multiple self-signed (root) certificates found"
        return nil, errors
      else
        root = cert
      end
    else
      issuer_map[ cert.issuer.to_s ] = cert
    end
  end
  if root == NIL
    errors << "Self-signed root certificate not found"
    return nil, errors
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
  end # sort_certs

  if tmp_list.size == 1
    errors << 'No issued certificates found'
    return certs, errors
  end

  if certs.size != tmp_list.size
    errors << 'Certificates do not form a complete chain'
    return certs, errors
  end
  # success: return sorted list (root ca is first, leaf is last)
  return tmp_list, nil
end # sort_certs

def pemify( string )
  [
    '-----BEGIN CERTIFICATE-----',
    string.gsub( /[\r ]+/, '' ).split( "\n" ).join.split( /(.{64})/ ).reject { |e| e.empty? },
    '-----END CERTIFICATE-----'
  ].flatten.join( "\n" )
end

def signature_namespace_and_prefix( doc )
  # If Signature's namespace is not in doc's namespace collection then it will be either
  #   * in Ns_Xmldsig declared as default namespace for Signature scope
  #   * or whacked beyond recognition
  doc_ns = doc.collect_namespaces
  if RUBY_VERSION < '1.9'
    # Hash#index will be deprecated in the ruby 1.9.x series. Is in here for 1.8.x
    if doc_ns.index( MStr::Ns_Xmldsig )
      prefix = doc_ns.index( MStr::Ns_Xmldsig ).split( 'xmlns:' ).last
    else
      prefix = 'xmlns'
    end
  else
    if doc_ns.key( MStr::Ns_Xmldsig )
      prefix = doc_ns.key( MStr::Ns_Xmldsig ).split( 'xmlns:' ).last
    else
      prefix = 'xmlns'
    end
  end
  sig_ns = { prefix => MStr::Ns_Xmldsig }
  return sig_ns, prefix
end

module MStr
  Ns_Xmldsig  = 'http://www.w3.org/2000/09/xmldsig#'
end # module MStr

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

def pad( padsize, item )
  "%#{ padsize }#{ { 'String' => 's', 'Fixnum' => 'd' }[ item.class.to_s ] }" % item
end

if ARGV.size != 1
  puts "Usage: #{ AppName } [-p,--prefix prefix] <Signed XML file>"
  exit
end

doc = get_xml ARGV[ 0 ]
sig_ns, prefix = signature_namespace_and_prefix( doc ) if doc
certs = extract_certs( doc, sig_ns, prefix ) if doc
certs, errors = sort_certs( certs ) if certs

if certs
  outfiles = Array.new
  certs.each_with_index do |cert, index|
    outfile = "#{ options.prefix }_#{ pad( certs.size.to_s.size, index ) }.pem"
    begin
      File.open( outfile, 'w' ) { |f| f.write cert.to_pem; f.close }
      outfiles << outfile
    rescue Exception => e
      puts e.inspect unless options.quiet
      exit 1
    end
  end
  puts "#{ certs.size } certificate#{ certs.size != 1 ? 's' : '' } extracted: #{ outfiles.inspect }" unless options.quiet
else
  puts "No certificates found" unless options.quiet
end

if errors
  errors.map { |e| puts e } unless options.quiet
  exit 1
end

exit 0

