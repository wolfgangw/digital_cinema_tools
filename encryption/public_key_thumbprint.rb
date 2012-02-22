#!/usr/bin/env ruby
#
# Calculate public key thumbprint of X509 certificates
# 2012 Wolfgang Woehl
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

require 'openssl'
require 'base64'

if ARGV.size < 1
  puts "Usage: #{ AppName } <cert> [more <certs>]"
  exit 1
end

ARGV.each do |arg|
  begin
    cert = OpenSSL::X509::Certificate.new( open arg )
  rescue Exception => e
    puts "#{ arg }: #{ e.inspect }"
    next
  end
  asn1 = Base64.decode64( cert.public_key.to_s.split( "\n" )[ 1 .. -2 ].join )
  public_key_thumbprint = OpenSSL::Digest.new( 'sha1', asn1 ).digest
  public_key_thumbprint_b64 = Base64.encode64( public_key_thumbprint ).chomp
  public_key_thumbprint_b16 = public_key_thumbprint.unpack( 'H2' * 20 ).join
  puts cert.subject.to_s
  puts "Public key thumbprint b64: #{ public_key_thumbprint_b64 } b16: #{ public_key_thumbprint_b16 }"
end

exit 0

