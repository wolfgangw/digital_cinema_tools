#!/usr/bin/ruby
# chromatic_adaptation.rb 
#
# latest changes: XYZ_to_xyY (unused), Rec.709 white point (to be confirmed)
#
# Calculate chromatic adaptation transformation matrix
#
# Put the result into env variables like 
#    export D65_to_DCI_Calibration_White="0.976531394318377  -0.0154596619959494 ..."
# to use with something like ImageMagick's "convert":
#    $ convert gradient.tiff [more options] -recolor "$D65_to_DCI_Calibration_White" [...] dci-gradient.tiff
#
# Math details: see http://www.brucelindbloom.com/
#
# Usage: chromatic_adaptation.rb --help
#        chromatic_adaptation.rb -s d50
#        chromatic_adaptation.rb -s d65 -d dci
#        chromatic_adaptation.rb --source d65 --destination dci --method bradford

require 'optparse'
require 'ostruct'
require 'matrix'

class Optparser
  def self.parse(args)
    # defaults
    options = OpenStruct.new
    options.source = "d65"
    options.destination = "dci_calibration_white"
    options.crd_definition = "bradford"
    options.output = 'line'

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: chromatic_adaptation.rb [ -s, --source | --d, --destination | -m, --method ]"

      opts.on( "-s", "--source k5900 | d50 | d55 | d65 (Default) | rec709 | d75 | dci_calibration_white", "White point reference of source" ) do |p|
        options.source = p
      end
      opts.on( "-d", "--destination k5900 | d50 | d55 | d65 | rec709 | d75 | dci_calibration_white (Default)", "White point reference of destination" ) do |p|
        options.destination = p
      end
      opts.on( "-m", "--method xyzscaling | bradford | vonkries", "Cone response domain definition" ) do |p|
        options.crd_definition = p
      end
      opts.on( "-o", "--output block | line (Default)", "Format output as a 3x3 block or as a line" ) do |p|
	options.output = p
      end
      
      opts.on_tail( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
      end
    end # Optionparser.new
    opts.parse!(args)
    options
  end # parse()
end # class Optparser
options = Optparser.parse(ARGV)

def t_to_xyY( t )
  if 4000 <= t and t <= 7000
    x = -4.6070 * 10 ** 9 / t ** 3 + 2.9678 * 10 ** 6 / t ** 2 + 0.09911 * 10 ** 3 / t + 0.244063
  elsif 7000 < t and t <= 25000
    x = -2.0064 * 10 ** 9 / t ** 3 + 1.9018 * 10 ** 6 / t ** 2 + 0.24748 * 10 ** 3 / t + 0.237040
  end
  y = -3.000 * x ** 2 + 2.870 * x - 0.275
  _Y = 1.0
  return x, y, _Y
end
def xyY_to_XYZ( x, y, _Y)
  _X = x * _Y / y
  _Y = _Y
  _Z = ( 1 - x - y ) * _Y / y
  return _X, _Y, _Z
end
def XYZ_to_xyY( _X, _Y, _Z )
  x = _X / ( _X + _Y + _Z )
  y = _Y / ( _X + _Y + _Z )
  _Y = _Y
  return x, y, _Y
end

# White points. Take with a grain of salt wrt rounding errors (D65/ITU Rec. 709)
EE_X, EE_Y, EE_Z    = 1.0,     1.0,     1.0
D50_X, D50_Y, D50_Z = 0.96422, 1.00000, 0.82521   # x = 0.3457, y = 0.3585
D55_X, D55_Y, D55_Z = 0.95682, 1.00000, 0.92149   # x = 0.3324, y = 0.3474
D65_X, D65_Y, D65_Z = 0.95047, 1.00000, 1.08883   # x = 0.3127, y = 0.329
                                    # ITU Rec. 709: x = 0.3127, y = 0.3290
REC709_X, REC709_Y, REC709_Z = 0.950455927051672, 1.0, 1.08905775075988
D75_X, D75_Y, D75_Z = 0.94972, 1.00000, 1.22638
                           # DCI Calibration White: x = 0.3140, y = 0.3510, Y=1.0 (48 cd/m**2)
DCI_Calibration_White_X, DCI_Calibration_White_Y, DCI_Calibration_White_Z = 0.894583, 1.00000, 0.954417
# The following is (apparently) offered by Adobe CS4 ("DCDM X'Y'Z' (gamma 2.6) 5900K (by Adobe)")
tmp_x, tmp_y, tmp_Y = t_to_xyY( 5900 )            # x = 0.324, y = 0.340
K5900_X, K5900_Y, K5900_Z = xyY_to_XYZ( tmp_x, tmp_y, tmp_Y )

# Cone response domain definitions, 3 methods:
M_A_XYZScaling = Matrix[
  [1.0, 0.0, 0.0],
  [0.0, 1.0, 0.0],
  [0.0, 0.0, 1.0]
]
M_A_Bradford = Matrix[
  [0.8951000, 0.2664000, -0.1614000],
  [-0.7502000, 1.7135000, 0.0367000],
  [0.0389000, -0.0685000, 1.0296000]
]
M_A_Von_Kries = Matrix[
  [0.4002400, 0.7076000, -0.0808100],
  [-0.2263000, 1.1653200, 0.0457000],
  [0.0000000, 0.0000000, 0.9182200]
]

case
  when options.source == "k5900" then X_WS, Y_WS, Z_WS = K5900_X, K5900_Y, K5900_Z
  when options.source == "d50" then X_WS, Y_WS, Z_WS = D50_X, D50_Y, D50_Z
  when options.source == "d55" then X_WS, Y_WS, Z_WS = D55_X, D55_Y, D55_Z
  when options.source == "d65" then X_WS, Y_WS, Z_WS = D65_X, D65_Y, D65_Z
  when options.source == "rec709" then X_WS, Y_WS, Z_WS = REC709_X, REC709_Y, REC709_Z
  when options.source == "d75" then X_WS, Y_WS, Z_WS = D75_X, D75_Y, D75_Z
  when options.source == "dci_calibration_white" then X_WS, Y_WS, Z_WS = DCI_Calibration_White_X, DCI_Calibration_White_Y, DCI_Calibration_White_Z
end
case
  when options.destination == "k5900" then X_WD, Y_WD, Z_WD = K5900_X, K5900_Y, K5900_Z
  when options.destination == "d50" then X_WD, Y_WD, Z_WD = D50_X, D50_Y, D50_Z
  when options.destination == "d55" then X_WD, Y_WD, Z_WD = D55_X, D55_Y, D55_Z
  when options.destination == "d65" then X_WD, Y_WD, Z_WD = D65_X, D65_Y, D65_Z
  when options.destination == "rec709" then X_WD, Y_WD, Z_WD = REC709_X, REC709_Y, REC709_Z
  when options.destination == "d75" then X_WD, Y_WD, Z_WD = D75_X, D75_Y, D75_Z
  when options.destination == "dci_calibration_white" then X_WD, Y_WD, Z_WD = DCI_Calibration_White_X, DCI_Calibration_White_Y, DCI_Calibration_White_Z
end
case
  when options.crd_definition == "xyzscaling" then M_A = M_A_XYZScaling
  when options.crd_definition == "bradford" then M_A = M_A_Bradford
  when options.crd_definition == "vonkries" then M_A = M_A_Von_Kries
end

# CRD, Cone response domain
CRD_S = M_A * Matrix[ [X_WS], [Y_WS], [Z_WS] ]
CRD_D = M_A * Matrix[ [X_WD], [Y_WD], [Z_WD] ]
rho_S, gamma_S, beta_S = CRD_S.row(0)[0], CRD_S.row(1)[0], CRD_S.row(2)[0]
rho_D, gamma_D, beta_D = CRD_D.row(0)[0], CRD_D.row(1)[0], CRD_D.row(2)[0]

# CAT, Chromatic adaptation transform
CAT = M_A ** -1 * Matrix[ 
                          [rho_D / rho_S, 0, 0],
                          [0, gamma_D / gamma_S, 0],
                          [0, 0, beta_D / beta_S] ]   * M_A

if options.output == 'block'
  puts "Chromatic adaptation transformation for #{options.source} -> #{options.destination} (CRD definition: #{options.crd_definition}): \n#{CAT.row(0).to_a.join('  ')}\n#{CAT.row(1).to_a.join('  ')}\n#{CAT.row(2).to_a.join('  ')}"
elsif options.output == 'line'
  puts "Chromatic adaptation transformation for #{options.source} -> #{options.destination} (CRD definition: #{options.crd_definition}): \n#{CAT.row(0).to_a.join(' ')} #{CAT.row(1).to_a.join(' ')} #{CAT.row(2).to_a.join(' ')}"
else
  puts "Use -o block or -o line (Default)"
end

