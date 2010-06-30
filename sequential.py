#!/usr/bin/env python

"""sequential.py takes a list of strings (which can be filenames) and checks for sequential numeric parts.
It returns orders and a composite string with markers for those parts.
Usage:   sequential.py <list>
Example: sequential.py motion_sequence/*"""

import re
import sys
import getopt
import os.path


def numeric_and_non_numeric_particles( token ):
    splits = re.split( '(\D+)', token )
    return splits


def test_continuous( list ):
    continuous = False
    order = ''
    step = 0
    continuity_broken = False
    for element in list:
        if re.match( '\d+', element ):
            numerical = True
        else:
            numerical = False
            break
    if numerical == True:
        init = int( list[ 1 ] ) - int( list[ 0 ] )
        for index, element in enumerate( list ):
            if index == len( list ) - 1:
                break
            else:
                step = int( list[ index + 1 ] ) - int( list[ index ] )
                if step == 0:
                    break
                elif step == init:
                    continue
                elif step != init:
                    continuity_broken = True
                    break
    if ( step != 0 and continuity_broken == False ):
        continuous = True
        if step > 0:
            order = 'ascending by ' + str( step )
        else:
            order = 'descending by ' + str( step )
    return continuous, order, step


def mark_uuid( string ):
    return re.sub( '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '[UUID]', string )


def check_sequential( args ):
    composite_token = ''
    sequence = False
    orders = []
    splits = []
    # split all tokens into numeric and non-numeric partices
    for token in args:
        splits.append( numeric_and_non_numeric_particles( os.path.basename( token ) ) )
    # check all particles
    for index, item in enumerate( splits[ 0 ] ):
        list = []
        for particles in splits:
            # catch dangling ends of variable-sized split lists
            if index > len( particles ) - 1: # nothing left to pick up here
                list.append( '' )
            else:
                list.append( particles[ index ] )
        continuous, order, step = test_continuous( list )
        if continuous == True:
            sequence = True
            orders.append( order )
            composite_token += '[' + str( list[ 0 ] ) + '-' + str( list[ -1 ] ) + ']'
        else:
            composite_token += str( list[ 0 ] )
    composite_token = mark_uuid( composite_token )
    return sequence, composite_token, orders
    

def report( number, sequence, composite_token, orders ):
    print number, 'items'
    if sequence == True:
        number_of_streams = len( orders )
        print number_of_streams, "Sequential", [ 'stream', 'streams' ][ ( number_of_streams > 1 ) ], "found", "(",
        for index, order in enumerate( orders ):
            print order,
            if number_of_streams > 1 and index < len( orders ) -1:
                print ',',
        print ")"
        print composite_token
    else:
        print "No numeric sequential streams found"


class Usage( Exception ):
    def __init__( self, msg ):
        self.msg = msg
        

def main( argv = None ):
    # parse command line options
    try:
        try:
            opts, args = getopt.getopt( sys.argv[ 1: ], "h", ["help"] )
        except getopt.error, msg:
            raise Usage( msg )
        # process options
        for o, a in opts:
            if o in ( "-h", "--help" ):
                print __doc__
        # process arguments
        if len( args ) > 1:
            sequence, composite_token, orders = check_sequential( args )
            report( len( args ), sequence, composite_token, orders )
        else:
            raise Usage( 'Need at least 2 items to check for sequential streams' )
    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "For help use --help"
        return 2


if __name__ == "__main__":
    sys.exit( main() )

