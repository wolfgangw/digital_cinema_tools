#!/usr/bin/env ruby
#
# x509_inspect.rb prints information about a chain of X509 certificates
# Copyright 2012-2017 Wolfgang Woehl
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
AppVersion = 'v0.2017.07.10'
#
# Usage:  x509_inspect.rb chain_0.pem [chain_1.pem [...]]
#         x509_inspect.rb chain_*
#         x509_inspect.rb chain_* -l file,cn,dnq,basicConstraints
#         x509_inspect.rb --help
#

require 'openssl'
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse( args )
    # defaults
    options = OpenStruct.new
    options.items = [ 'o', 'ou', 'cn', 'dnq', 'serial' ]
    options.items_all = %w[ file version serial signature_algorithm not_before not_after o ou cn dnq o_issuer ou_issuer cn_issuer dnq_issuer basicConstraints keyUsage authorityKeyIdentifier pubkey exponent ]
    options.detect_chain = true

    opts = OptionParser.new do |opts|
      # Banner and usage
      opts.banner = <<BANNER
#{ AppName } #{ AppVersion }
Usage: #{ AppName } [-l,--list <item1,item2,...>] [-a,--all] [--no-chain] [-h,--help] <certs>
Items:
  file version serial signature_algorithm not_before not_after
  o ou cn dnq o_issuer ou_issuer cn_issuer dnq_issuer
  basicConstraints keyUsage authorityKeyIdentifier
  pubkey exponent
Default items:
  o ou cn dnq serial

BANNER

      # Options
      opts.on( '-l', '--list list', Array, "List of items to be displayed (Default: 'o,ou,cn,dnq,serial')" ) do |p|
        options.items = p
      end
      opts.on( '-a', '--all' ) do
        options.items = options.items_all
      end
      opts.on( '--no-chain', 'Do not try to detect and sort chain' ) do
        options.detect_chain = false
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

module OpenSSL module X509 class Certificate
  attr_accessor :file
end end end

def pemfiles_to_obj( list )
  certs = Array.new
  list.each do |pemfile|
    begin
      certs << OpenSSL::X509::Certificate.new( open pemfile )
      certs.last.file = pemfile
    rescue Exception => e
      puts e.inspect
    end
  end
  return certs
end

def sort_certs( certs )
  # Find root ca and collect issuers
  # ruby version of CTP's dsig_cert.py
  root = nil
  issuer_map = Hash.new
  errors = Array.new

  certs.each do |cert|
    if cert.issuer.to_s == cert.subject.to_s
      if root
        errors << "Multiple self-signed (root) certificates found"
        return [], errors
      else
        root = cert
      end
    else
      issuer_map[ cert.issuer.to_s ] = cert
    end
  end
  if root == nil
    errors << "Self-signed root certificate not found"
    return [], errors
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
    errors << 'No issued certificates found'
    return certs, errors
  end

  if certs.size != tmp_list.size
    errors << 'Certificates do not form a complete chain'
    return certs, errors
  end
  # root ca is first, last is leaf
  return tmp_list, nil
end # sort_certs

def name_field( fieldname, x509_name )
  x509_name.to_a.find_all { |e| e.first.match '^' + fieldname + '$' }.flatten[ 1 ]
end

def pad_column( string, column )
  string.ljust( column.max_by( &:length ).size )
end

def extension_values( string )
  string.split( ', ' )
end

def extension( cert, oid )
  cert.extensions.each do |x|
    case x.oid
    when oid
      return x.value
    end
  end
end

def name_fields_canon
  {
    'o' => 'O',
    'ou' => 'OU',
    'cn' => 'CN',
    'dnq' => 'dnQualifier'
  }
end

Methmap = {
  'pubkey' => lambda { |cert| cert.public_key.n },
  'exponent' => lambda { |cert| cert.public_key.e },
}
Methmap[ 'version' ] = lambda { |cert| ( cert.send 'version' ).to_i + 1 }
%w( file serial signature_algorithm not_before not_after ).each do |item|
  Methmap[ item ] = lambda { |cert| cert.send item }
end
%w( o ou cn dnq o_issuer ou_issuer cn_issuer dnq_issuer ).each do |item|
  Methmap[ item ] = lambda { |cert| name_field( name_fields_canon[ item.split( '_' ).first ], ( item =~ /issuer$/ ? cert.issuer : cert.subject ) ) }
end
%w( basicConstraints keyUsage authorityKeyIdentifier ).each do |item|
  Methmap[ item ] = lambda { |cert| extension( cert, item ) }
end

def x509_inspect( certs, options )
  report = Array.new
  certs.each do |cert|
    cert_list_of_items = Array.new
    options.items.each do |item|
      cert_list_of_items << { item => Methmap[ item ].call( cert ) } if Methmap.keys.include? item
    end
    report << cert_list_of_items
  end
  report
end

def puts_padded( report, spacer )
  report.each do |cert_items|
    line = Array.new
    cert_items.each_with_index do |item, index|
      line << pad_column( item.inspect, column = report.collect { |items| items[ index ].inspect } )
    end
    puts line.join spacer
  end
end

if ARGV.empty?
  puts "Usage: #{ AppName } [-l,--list <item1,item2,...>] [--no-chain] [-h,--help] <certs>"
  exit 1
end

certs = pemfiles_to_obj( ARGV )
certs, errors = sort_certs( certs ) unless certs.size < 2 or options.detect_chain == false
report = x509_inspect( certs, options )
puts_padded( report, spacer = ' ' )

if errors
  errors.map { |e| puts e }
  exit 1
end

exit 0

