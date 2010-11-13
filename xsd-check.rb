#!/usr/bin/env ruby

# Check a number of XML documents against 1 Schema file, quick and dirty. Thank you, nokogiri!
#
# xsd-check.rb <Schema file> <XML document> (order doesn't matter)
# xsd-check.rb SMPTE-429-7-2006-CPL.xsd cpl_2f1eb7bc-28ec-4590-a71c-cf564df4ecad_.xml
#
# In the good tradition of schema validators: No messages means no errors

require 'rubygems'
require 'nokogiri'

args = ARGV
docs = Array.new
schema = ''
args.each do |arg|
  if arg =~ /.xsd$/
    schema = arg
  elsif arg =~ /.xml$/
    docs << arg
  end
end

puts "Schema: #{ File.basename( schema ) }"
puts "XML docs: #{ docs.inspect }"

unless schema == '' or docs.empty?
  xsd = Nokogiri::XML::Schema( File.read( schema ) )
  docs.each do |doc|
    xml = Nokogiri::XML( File.read( doc ) )
    puts "Validating #{ doc } ..."
    xsd.validate( doc ).each do |error|
      puts "Error: #{ error.message }"
    end
  end
end
