#!/usr/bin/ruby
# rec709-xyz_matrix.rb
#
# For now this script produces 1 3x3 matrix (ITU Rec. 709 to XYZ) to verify numbers
#
# Output:
# ITU Rec. 709 to XYZ matrix:
# 0.412390799265959  0.357584339383878  0.180480788401834
# 0.21263900587151  0.715168678767756  0.0721923153607337
# 0.0193308187155918  0.119194779794626  0.950532152249661
# 
# Math details and notes: see http://www.brucelindbloom.com/Eqn_RGB_XYZ_Matrix.html

require 'matrix'

def xyY_to_XYZ( x, y, _Y)
  _X = x * _Y / y
  _Y = _Y
  _Z = ( 1 - x - y ) * _Y / y
  return _X, _Y, _Z
end

# ITU Rec. 709
rec709_R_x, rec709_R_y = 0.64, 0.33 # see http://en.wikipedia.org/wiki/Rec._709
rec709_G_x, rec709_G_y = 0.30, 0.60
rec709_B_x, rec709_B_y = 0.15, 0.06
# rec709_reference_white_x, rec709_reference_white_y = 0.3127, 0.3290
rec709_reference_white_X, rec709_reference_white_Y, rec709_reference_white_Z = xyY_to_XYZ(0.3127, 0.3290, 1) # X = 0.950455927051672, Y= 1, Z = 1.08905775075988

x_r, y_r = rec709_R_x, rec709_R_y
x_g, y_g = rec709_G_x, rec709_G_y
x_b, y_b = rec709_B_x, rec709_B_y
X_W, Y_W, Z_W = rec709_reference_white_X, rec709_reference_white_Y, rec709_reference_white_Z

X_r = x_r / y_r
Y_r = 1
Z_r = ( 1 - x_r - y_r ) / y_r
X_g = x_g / y_g
Y_g = 1
Z_g = ( 1 - x_g - y_g ) / y_g
X_b = x_b / y_b
Y_b = 1
Z_b = ( 1 - x_b - y_b ) / y_b

S = 
  Matrix[ [X_r, X_g, X_b], 
          [Y_r, Y_g, Y_b], 
          [Z_r, Z_g, Z_b] ] ** -1 * 
  Matrix[ [X_W], 
          [Y_W], 
          [Z_W] ]
S_r, S_g, S_b = S.row(0)[0], S.row(1)[0], S.row(2)[0]
RGB_to_XYZ = Matrix[  [S_r * X_r, S_g * X_g, S_b * X_b], 
                      [S_r * Y_r, S_g * Y_g, S_b * Y_b], 
                      [S_r * Z_r, S_g * Z_g, S_b * Z_b] ]

puts "ITU Rec. 709 to XYZ matrix:\n#{RGB_to_XYZ.row(0).to_a.join('  ')}\n#{RGB_to_XYZ.row(1).to_a.join('  ')}\n#{RGB_to_XYZ.row(2).to_a.join('  ')}"
