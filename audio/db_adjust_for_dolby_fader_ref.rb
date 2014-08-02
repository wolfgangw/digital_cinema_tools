#!/usr/bin/env ruby
#
# Calculate required attenuation/amplification,
# given two Dolby CP650/750 Main Fader Knob values:
#
#   Desired fader setting (default 7.0)
#   Actual fader setting
#
#   e.g.
#   db_adjust_for_dolby_fader_ref.rb -t 7.0 -i 4.5
#
# See Dolby CP650/750 manuals, section Main Fader Knob:
#
# "When the fader knob is rotated between readings 0 and 4.0,
# the output level changes in 20 dB steps between –90 and –10 dB.
# When the fader knob is rotated between readings 4.0 and 10,
# the output level changes in 3 1/3 dB steps between –10 and +10 dB."
#
# Wolfgang Woehl 2013
#

require 'optparse'
require 'ostruct'

AppName = File.basename __FILE__
AppVersion = 'v0.2013.12.30'

class Optparser
  def self.parse( args )
    # defaults
    options = OpenStruct.new
    options.fader_target = 7.0
    options.fader_input = nil

    opts = OptionParser.new do |opts|

      # Banner and usage
      opts.banner = <<BANNER
#{ AppName } #{ AppVersion }
Usage: #{ AppName } -i|--input <Dolby CP650/750 Main Fader Knob value> [-t|--target <Dolby CP650/750 Main Fader Knob value>]

BANNER

      # Options
      opts.on( '-i', '--input value', Float, "Specify actual Dolby CP650/750 Main Fader Knob value" ) do |p|
        options.fader_input = p
      end
      opts.on( '-t', '--target value', Float, "Specify desired Dolby CP650/750 Main Fader Knob value (Default: 7.0)" ) do |p|
        options.fader_target = p
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

if options.fader_input.nil?
  puts "At least input/actual fader setting required. See #{ AppName } --help"
  exit 1
end

# Check valid range 0.0 - 10.0
fader_out_of_range = FALSE
[ 'Fader input', 'Fader target' ].each do |moniker|
  var_name = moniker.downcase.gsub( ' ', '_' )
  if options.send( var_name ) < 0.0 or options.send( var_name ) > 10.0
    puts "#{ moniker } '#{ options.send( var_name ) }' out of range. Specify a value between 0.0 and 10.0"
    fader_out_of_range = TRUE
  end
end
exit 1 if fader_out_of_range

# Round to 1 decimal place which is what the Dolby Main Fader Knob will provide
[ 'Fader input', 'Fader target' ].each do |moniker|
  var_name = moniker.downcase.gsub( ' ', '_' )
  rounded = options.send( var_name ).round( 1 )
  if rounded != options.send( var_name )
    puts "#{ moniker } '#{ options.send( var_name ) }' rounded to #{ rounded }"
    options.send( "#{ var_name }=", rounded )
  end
end

# See Dolby CP650/750 manuals (section Main Fader Knob) for the math
def dolby_fader_to_db( fader )
  if fader <= 4.0
    -90.0 + fader * 20
  else
    -10.0 + ( fader - 4.0 ) * 20/6
  end
end

def att_or_amp?( val )
  val <= 0 ? 'attenuation' : 'amplification'
end

fader_input = options.fader_input
fader_target = options.fader_target

fader_input_db = dolby_fader_to_db fader_input
fader_target_db = dolby_fader_to_db fader_target

required_level_change = fader_input_db - fader_target_db

puts "Dolby CP650/750 fader: You're actually playing at #{ fader_input } (#{ "%.3f" % fader_input_db } dB #{ att_or_amp? fader_input_db })"
puts "Dolby CP650/750 fader: You want to play at #{ fader_target } (#{ "%.3f" % fader_target_db } dB #{ att_or_amp? fader_target_db })"
if fader_input == fader_target
  puts "No level change required"
else
  puts "Dolby CP650/750 fader: In order to achieve #{ fader_target } fader setting change levels by #{ "%.3f" % required_level_change } dB"
end

