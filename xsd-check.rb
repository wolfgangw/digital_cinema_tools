#!/usr/bin/env ruby
#
# Wolfgang Woehl v0.2011.12.29
#
# Validate XML document against XSD.
# Quick and dirty. Thank you, libxml and nokogiri!
#
# xsd-check.rb <Schema file> <XML document>
# xsd-check.rb SMPTE-429-7-2006-CPL.xsd cpl.xml
#
# For XML Catalog operation see env XML_CATALOG_FILES and XML_DEBUG_CATALOG
#

require 'rubygems'
require 'nokogiri'

if ARGV.size == 2
  args = ARGV
  if args.first == args.last
    puts "Identical files provided"
    exit
  end
else
  puts "2 arguments required: 1 XML file, 1 XSD file (Order doesn't matter)"
  exit
end

if ENV[ 'XML_CATALOG_FILES' ].nil?
  puts 'Consider using XML Catalogs and set env XML_CATALOG_FILES to point at your catalog'
end

def abort_on_errors( errors )
  if ! errors.empty?
    errors.map { |e| puts e.inspect }
    abort "Document is not valid"
  end
end

errors = Array.new
schema = ''
doc = ''

args.each do |arg|
  begin
    xml = Nokogiri::XML( open arg )
  rescue Exception => e
    errors << e
    abort_on_errors( errors )
  end
  unless xml.errors.empty?
    xml.errors.each do |e|
      errors << e
    end
  end
  if xml.root
    case xml.root.node_name
    when 'schema'
      schema = arg
    else
      doc = arg
    end
  else
    errors << "Not XML"
  end
end
abort_on_errors( errors )

begin
  xsd = Nokogiri::XML::Schema( open schema )
rescue Exception => e
  errors << e
  abort_on_errors( errors )
end

schema_errors = xsd.validate( doc )
if ! schema_errors.empty?
  schema_errors.each do |error|
    errors << error
    puts "Validation: #{ doc }: #{ error.message }"
  end
else
  puts "XML document is valid"
end

if ! errors.empty?
  errors.each do |e|
    if e.message.match /Element.*No matching global.*declaration available/
      puts 'Wrong XSD file?'
    end
  end
  puts "XML document is not valid"
end

