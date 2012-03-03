#!/usr/bin/env ruby
#
# digest-test-runs.rb will run digest calculations over File#IO
# 2012 Wolfgang Woehl
#
AppName = File.basename __FILE__

require 'openssl'
require 'optparse'
require 'ostruct'

class Optparser
  def self.parse( args )
    # defaults
    options = OpenStruct.new
    options.digest_algorithm = 'sha1'
    options.chunksize = 4096
    options.runs = 1

    opts = OptionParser.new do |opts|

      # Banner and usage
      opts.banner = <<BANNER
Usage: #{ AppName } <file> [-d,--digest-algorithm <algorithm>] [-c,--chunksize <file io chunksize>] [-r,--runs <number of test runs>]
BANNER

      # Options
      opts.on( '-d', '--digest-algorithm alg', String, 'Digest algorithm (Default: sha1)' ) do |p|
        options.digest_algorithm = p
      end
      opts.on( '-c', '--chunksize chunksize', Integer, 'File IO chunksize (Default: 4096)' ) do |p|
        options.chunksize = p
      end
      opts.on( '-r', '--runs runs', Integer, 'Number of test runs' ) do |p|
        options.runs = p
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
    return options, opts
  end
end
options, opts = Optparser.parse( ARGV )
if ARGV.size != 1
  puts opts.banner
  exit 1
end
arg = ARGV.first

class Numeric
  TERA = 1099511627776.0
  GIGA = 1073741824.0
  MEGA = 1048576.0
  KILO = 1024.0
  def to_k
    case
    when self == 1 then "1 Byte"
    when self < KILO then "%d Bytes" % self
    when self < MEGA then "%.3f KB" % ( self / KILO )
    when self < GIGA then "%.3f MB" % ( self / MEGA )
    when self < TERA then "%.3f GB" % ( self / GIGA )
    else "%.3f TB" % ( self / TERA )
    end
  end
end

class Eta
  attr_reader :percentage, :eta, :elapsed
  def initialize( title, width, looks_like, terminal_size, bytes )
    @title = title
    @total = 100
    @scaling = width.to_f / @total
    @left, @major, @fill, @right = looks_like.scan( /./ )
    @terminal_size = terminal_size
    @bytes = bytes
    @start = Time.now
  end

  def update( percentage )
    @percentage = percentage
    eta
  end

  def eta
    return if @percentage == 0
    @elapsed = Time.now - @start
    @eta = @elapsed * @total / @percentage - @elapsed
  end

  def update_terminal( percentage )
    update( percentage )
    line = bar
    if @terminal_size and line.length > @terminal_size[ :columns ]
      line = ' [...] ' + line[ line.length - @terminal_size[ :columns ] + 7 .. -1 ]
    end
    printf "%s\r", line
  end

  def clear_terminal
    printf "%s\r", ' ' * bar.size
  end

  def preserve_terminal
    puts
  end

  def preserve_terminal_title_with_message( message )
    clear_terminal
    puts [ @title, message ].join( ' ' )
  end

  def time_string( head, t )
    return "%s --:--:--" % head if t.nil?
    t = t.to_i; s = t % 60; m  = ( t / 60 ) % 60; h = t / 3600
    "%s %02d:%02d:%02d" % [ head, h, m, s ]
  end

  def bps
    "#{ ( @bytes / @total * @percentage / @elapsed ).to_k }/sec" if @elapsed
  end

  private

  def bar
    [ @title, percentage_pad, inner_bar, tail ].join( ' ' )
  end

  def percentage_pad
    "%3s%" % @percentage
  end

  def inner_bar
    @left + @major * ( @percentage * @scaling ).ceil + @fill * ( ( @total - @percentage ) * @scaling ).floor + @right
  end

  def tail
    [ time_string( 'ETA', @eta ), time_string( 'Elapsed', @elapsed ), bps ].join( ' ' )
  end
end # Eta

def command_exists?(command)
  ENV[ 'PATH' ].split( File::PATH_SEPARATOR ).any? { |d| File.exists? File.join( d, command ) }
end

def detect_terminal_size
  if command_exists?( 'tput' )
    { :columns => `tput cols`.to_i, :lines => `tput lines`.to_i }
  else
    nil
  end
end


def digest_with_etabar( options, title, file, pbar_width = 50, looks_like = '[= ]' )
  bytes = File.size file
  chunksize = 4096
  chunks = bytes / chunksize + ( bytes % chunksize > 0 ? 1 : 0 )
  chunks_per_percent = chunks / 100 + 1

  begin
    dgst = OpenSSL::Digest.new( options.digest_algorithm )
  rescue Exception => e
    puts e.message
    exit 1
  end
  io = File.open file
  eta = Eta.new( title, pbar_width, looks_like, detect_terminal_size, bytes )

  ( 0 .. 100 ).each do |percentage|
    # read 1 % of chunks
    chunks_per_percent.times do 
      chunk = io.read( chunksize )
      dgst.update chunk if chunk
    end
    eta.update_terminal percentage
  end

  return dgst.digest, eta
end

#
# See http://www.kernel.org/doc/Documentation/sysctl/vm.txt
# drop_caches
#
# Writing to this will cause the kernel to drop clean caches, dentries and
# inodes from memory, causing that memory to become free.
#
# To free pagecache:
#   echo 1 > /proc/sys/vm/drop_caches
# To free dentries and inodes:
#   echo 2 > /proc/sys/vm/drop_caches
# To free pagecache, dentries and inodes:
#   echo 3 > /proc/sys/vm/drop_caches
#
# As this is a non-destructive operation and dirty objects are not freeable, the
# user should run `sync' first.
#

if command_exists?( 'sysctl' )
  drop_caches_status = `sysctl vm.drop_caches`.chomp
end

if File.exists? arg and File.file? arg
  puts "Digest algorithm:#{ options.digest_algorithm }  Runs:#{ options.runs }  Chunksize:#{ options.chunksize }  File:#{ arg }  Filesize:#{ ( File.size arg ).to_k }  #{ drop_caches_status }"

  options.runs.times do |i|
    header = "%#{ options.runs.to_s.size }s" % ( i + 1 ) + "/#{ options.runs }"
    digest, eta = digest_with_etabar( options, title = header, file = arg, pbar_width = 30, looks_like = '[= ]' )
    eta.preserve_terminal_title_with_message [ eta.time_string( 'Time', eta.elapsed ), "Rate %s/sec" % ( File.size( arg ) / eta.elapsed ).to_k ].join ' '
  end
else
  puts "File #{ arg } doesn't exist/not a file"
  puts opts.banner
  exit 1
end

exit 0

