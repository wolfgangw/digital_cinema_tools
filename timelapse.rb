#!/usr/bin/env ruby
#
# v0.2012.06.10
# Wolfgang Woehl 2011
# A no-frills timelapse tool to capture a sequence of screenshots
# Needs ImageMagick's import tool
#
# Usage: timelapse.rb -d,--duration <N[s|m|h]> --fps <FPS> -o,--out <DIRNAME> -s,--size <widthxheight> [-q,--quality <im quality 0-100>]
# Example: $ timelapse.rb --duration 1h --fps 1 --out sequence --size 1920x1080 --quality 100
#

require 'rubygems'
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse(args)
    # defaults
    options = OpenStruct.new
    options.duration = NIL
    duration_re = /^\d+[smh]$/ # 
    options.fps = NIL
    options.out = NIL
    options.size = NIL
    size_re = /\d+(\.\d+)?x\d+(\.\d+)?/
    options.quality = 92 # default im quality

    opts = OptionParser.new do |opts|
      opts.banner = "#{ File.basename( $0 ) } -d, --duration <N[s|m|h]> --fps <FPS> -o,--out DIRNAME -s,--size <WIDTHxHEIGHT> [-q, --quality <JPEG quality>]"

      opts.on( '-d', '--duration duration', String, "How long to record images. Specify a number and append 's', 'm' or 'h' for seconds, minutes or hours" ) do |p|
        if p =~ duration_re
          options.duration = p
          # FIXME the regexp works for '1', '1.' and '1.2' but the reject seems to mess things up
          count, base = p.split(/(\d+(\.\d+)?)/).reject {|e| e.empty? }
          options.duration_in_seconds =
            case base
            when 's'
              count.to_f
            when 'm'
              count.to_f * 60
            when 'h'
              count.to_f * 60 * 60
            end
        end
      end
      opts.on( '--fps fps', Float, 'Framerate' ) do |p|
        options.fps = p if p > 0
      end
      opts.on( '-o', '--out outdir', String, 'Output directory. Will be created if needed and possible' ) do |p|
        options.out = p
      end
      opts.on( '-s', '--size size', String, "Image size to generate. Use WIDTHxHEIGHT" ) do |p|
        if p =~ size_re
          options.size = p
        end
      end
      opts.on( '-q', '--quality quality', Integer, 'JPEG quality. Use a number between 1 (strongest compression) and 100 (least compression)' ) do |p|
        options.quality = p if p >= 0 and p <= 100
      end
      opts.on_tail( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
      end
    end # opts = OptionParser.new do
      begin
        opts.parse!(args)
        options
      rescue OptionParser::ParseError
        $stderr.print "Error: " + $! + "\n"
        exit
      end
  end # self.parse
end
options = Optparser.parse(ARGV)

def confirm_or_create( location )
  # location (a directory) might exist and be either writeable or not.
  # it might not exist and be either writeable (read 'can be created') or not.
  # since we want to be able to specify a "deep" path (topdir/with/children/...) File.writable?() wouldn't work.
  testfile = File.join( location, `uuidgen`.chomp )
  if File.exists?( location )
    begin
      result = `touch #{ testfile } > /dev/null 2>&1`
      File.delete( testfile )
      return TRUE # location exists and we can write to it
    rescue Exception => result
      puts result
      return FALSE # location exists but we can't write to it
    end
  else
    begin
      result = Dir.mkdir( location )
      return TRUE # location created, hence writeable
    rescue Exception => result
      puts result
      return FALSE
    end
  end
end

def hours_minutes_seconds_verbose( seconds )
  t = seconds
  hrs = ( ( t / 3600 ) ).to_i
  min = ( ( t / 60 ) % 60 ).to_i
  sec = t % 60
  return [
    hrs > 0 ? hrs.to_s + " hour#{ 's' * ( hrs > 1 ? 1 : 0 ) }" : nil ,
    min > 0 ? min.to_s + " minute#{ 's' * ( min > 1 ? 1 : 0 ) }" : nil ,
    sec == 1 ? sec.to_i.to_s + ' second' : sec != 0 ? sec.to_s + ' seconds' : nil ,
    t > 60 ? "(#{ t } seconds)" : nil
  ].compact.join( ' ' )
end

# all options required
bailout = FALSE
missing_options = []
[ 'out', 'duration', 'fps', 'size', ].each do |o|
  if options.send( o ).nil?
    missing_options << o
    bailout = TRUE
  end
end
if bailout == TRUE
  puts "Missing option#{ missing_options.size != 1 ? 's' : '' }: #{ missing_options.join( ', ' ) }"
  puts "All options required (except -q | --quality). See #{ File.basename( $0 ) } -h for options"
  exit
end

if confirm_or_create( options.out ) == FALSE
  exit
end
total_frames = ( options.duration_in_seconds * options.fps ).to_i
padding = "%0#{ total_frames.to_s.size }d"
sleep = 1.0 / options.fps

puts "Going to write #{ total_frames } frames (dim: #{ options.size } q: #{ options.quality }) over #{ hours_minutes_seconds_verbose( options.duration_in_seconds ) } @ #{ options.fps } fps"
puts "Sequence @ 25fps will last #{ hours_minutes_seconds_verbose( total_frames.to_f / 25 ) } (Factor: #{ options.duration_in_seconds / ( total_frames.to_f / 25 ) })"

( 1 .. total_frames ).each do |n|
  filename = File.join( options.out, padding % n + '.jpg' )
  printf "#{ filename }\r"; STDOUT.flush
  `import -window root -quality #{ options.quality } -resize #{ options.size } #{ filename }`
  `sleep #{ sleep }`
end

output_size = `du -sh #{ options.out }`.split( /\s/ ).first
printf "#{ '-' * 50 }\r"; STDOUT.flush
puts "Wrote #{ total_frames } frames (dim: #{ options.size } q: #{ options.quality } du: #{ output_size }) over #{ hours_minutes_seconds_verbose( options.duration_in_seconds ) } @ #{ options.fps } fps"
puts "Sequence @ 25fps will last #{ hours_minutes_seconds_verbose( total_frames.to_f / 25 ) } (Factor: #{ options.duration_in_seconds / ( total_frames.to_f / 25 ) })"
puts 'Done'

