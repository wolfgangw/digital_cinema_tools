#!/usr/bin/env ruby
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse( args )
    options = OpenStruct.new # placeholder
    opts = OptionParser.new do |opts|
      opts.banner = <<BANNER
#{ File.basename( $0 ) } takes a list of strings (which can be filenames) and checks for sequential numeric parts.
It returns orders and a composite string with markers for those parts.
Usage:   #{ File.basename( $0 ) } <list>
Example: #{ File.basename( $0 ) } motion_sequence/*
BANNER
      opts.on_tail( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
      end
    end
    opts.parse!( args )
    options
  end 
end
options = Optparser.parse( ARGV )

def numeric_and_non_numeric_particles( token )
  token.split( /(\D+)/ )
end

def continuous?( list )
  continuous = FALSE
  order = NIL
  step = 0
  continuity_broken = FALSE
  init = list[ 1 ].to_i - list[ 0 ].to_i
  list.each_with_index do |element, index|
    unless element == list.last
      step = list[ index + 1 ].to_i - list[ index ].to_i
      if step == 0
        break
      elsif step == init
        next
      elsif step != init
        continuity_broken = TRUE
      end
    end
  end
  if step != 0 and continuity_broken == FALSE
    continuous = TRUE
    step > 0 ? order = "ascending by #{ step }" : order = "descending by #{ step }"
  end
  return continuous, order, step
end

# RFC 4122 compliant UUID's are lowercase only
def mark_uuid( token )
  token.gsub( /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, '[UUID]' )
end

if ! ARGV.empty?
  tokens = ARGV
else
  puts 'No list specified'
  exit
end
composite_token = ''
sequence = FALSE
orders = Array.new
particles = Array.new

# split all tokens into numeric and non-numeric partices
tokens.each_with_index do |token, index|
  particles[ index ] = numeric_and_non_numeric_particles( File.basename( token ) )
end

# check all particles
particles.first.each_with_index do |item, index|
  list = Array.new
  # collect column
  particles.each do |particle|
    list << particle[ index ]
  end
  continuous, order, step = continuous?( list )
  if continuous == TRUE
    sequence = TRUE
    orders << order
    composite_token += "[#{ list.first }-#{ list.last }]"
  else
    composite_token += "#{ list.first }"
  end
end
composite_token = mark_uuid( composite_token )
puts "#{ tokens.size } item#{ 's' * ( tokens.size > 1 ? 1 : 0 ) }"
if sequence == TRUE
  puts "Sequence (#{ orders.join( ', ' ) })"
  puts composite_token
else
  puts "Not a sequence"
end

