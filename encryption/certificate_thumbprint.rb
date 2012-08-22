#!/usr/bin/env ruby
#
# certificate_thumbprint.rb computes certificate thumbprint(s) as
# specified in ST 430-2 Digital Certificate
# (section 5.4 Certificate and Public Key Thumbprint)
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
AppVersion = 'v0.2012.08.22'
#
# Usage: certificate_thumbprint.rb <path to X.509 cert file> | <path to X.509 certificate chain file> [<more of these ...>]
#

require 'tempfile'
require 'pp'
require 'openssl'

def dc_thumbprint( cert_obj )
  cert_file = Tempfile.new( AppName )
  File.open( cert_file.path, 'w' ) { |f| f.write cert_obj.to_pem }
  tmp = Tempfile.new( AppName )
  `openssl asn1parse -in #{ cert_file.path } -out #{ tmp.path } -noout -strparse 4`
  `openssl dgst -sha1 -binary #{ tmp.path } | openssl base64`.chomp
end

if ARGV.size == 0
  puts "Usage: #{ AppName } <path to X.509 Certificate file> [<more> ...]"
  exit 1
end

dc_thumbprints = Hash.new
ARGV.each do |arg|
  if File.exists? arg
    begin
      raw = File.read arg
    rescue Exception => e
      puts e.inspect
    end

    if raw
      dc_thumbprints[ arg ] = Array.new
      cert_candidates = raw.scan( /-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m )
      cert_candidates.each do |cert_candidate|
        begin
          cert = OpenSSL::X509::Certificate.new cert_candidate
          dc_thumbprints[ arg ] << [ dc_thumbprint( cert ), cert.subject.to_s ].join( ': ' ) if cert.is_a?( OpenSSL::X509::Certificate )
        rescue Exception => e
          dc_thumbprints[ arg ] << e.inspect
        end
      end
    end

  else # file arg not found
    puts "File #{ arg } not found"
  end
end # ARGV.each

pp dc_thumbprints
exit 0

