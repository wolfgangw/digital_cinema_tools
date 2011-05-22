#!/usr/bin/env python

"""sequential.py checks a list of strings (e.g. filenames) for numeric sequential streams.
TODO: obj.<gaps>
    
It creates a SequentialCandidate object which provides these attributes:
    obj.args:      List of processed strings
    obj.number_of_args
    obj.sequence:  True|False (True if at least 1 continuous numeric sequential stream is found)
    obj.composite: Composite summary of obj.args with markers for numeric sequential streams and UUIDs
    obj.orders:    List of sequential stream directions
and
    obj.report()

Usage:   sequential.py <list>
Example: sequential.py motion_sequence/*"""

import re
import sys
import getopt
import os.path

class SequentialCandidate:
    
    def __init__( self, args ):
        self.args = args
        self.number_of_args = len( self.args )
        args_uuid_safe = []
        self.uuid_re = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        if re.search( self.uuid_re, self.args[ 0 ] ):
            args_uuid_safe = map( self._mark_uuid, self.args )
        else:
            args_uuid_safe = self.args
        self._check_sequential( args_uuid_safe )

    def _check_sequential( self, args ):
        self.composite = ''
        self.sequence = False
        self.orders = []
        splits = []
        for token in args:
            splits.append( self._numeric_and_non_numeric_particles( os.path.basename( token ) ) )
        for index in range( len( splits[ 0 ] ) ):
            column = []
            for row in splits:
                # catch dangling ends of variable-sized split lists
                if index > len( row ) - 1:
                    column.append( '' )
                else:
                    if re.match( '\d+', row[ index ] ):
                        numerical = True
                        column.append( row[ index ] )
                    else:
                        numerical = False
                        column.append( row[ index ] )
            if numerical == True:
                continuous, order, step = self._test_continuity( column )
            else:
                continuous = False
            if continuous == True:
                self.sequence = True
                self.orders.append( order )
                self.composite += '[' + str( column[ 0 ] ) + '-' + str( column[ -1 ] ) + ']'
            else:
                if len( list( set( column ) ) ) == 1:
                    self.composite += str( column[ 0 ] )
                else:
                    self.composite += '[GARBLED]'
        
    def _numeric_and_non_numeric_particles( self, token ):
        splits = re.split( '(\D+)', token )
        return splits

    def _test_continuity( self, sequence ):
        continuous = False
        continuity_broken = False
        order = ''
        step = 0
        initial_step = int( sequence[ 1 ] ) - int( sequence[ 0 ] )
        for index, element in enumerate( sequence ):
            if index == len( sequence ) - 1:
                break
            else:
                step = int( sequence[ index + 1 ] ) - int( sequence[ index ] )
                if step == 0:
                    break
                elif step == initial_step:
                    continue
                elif step != initial_step:
                    continuity_broken = True
                    break
        if ( step != 0 and continuity_broken == False ):
            continuous = True
            if step > 0:
                order = 'ascending by ' + str( step )
            else:
                order = 'descending by ' + str( step )
        return continuous, order, step

    def _mark_uuid( self, string ):
        return re.sub( self.uuid_re, '[UUID]', string )

    def report( self ):
        print self.number_of_args, 'items'
        if self.sequence == True:
            number_of_streams = len( self.orders )
            print number_of_streams, "numeric sequential", [ 'stream', 'streams' ][ ( number_of_streams > 1 ) ], "found", "(",
            for index, order in enumerate( self.orders ):
                print order,
                if number_of_streams > 1 and index < len( self.orders ) -1:
                    print ',',
            print ")"
            print self.composite
        else:
            print "No numeric sequential streams found"
            print self.composite

class Usage( Exception ):
    def __init__( self, msg ):
        self.msg = msg
        
def main( argv = None ):
    try:
        try:
            opts, args = getopt.getopt( sys.argv[ 1: ], "h", ["help"] )
        except getopt.error, msg:
            raise Usage( msg )
        for o, a in opts:
            if o in ( "-h", "--help" ):
                print __doc__
        if len( args ) > 1:
            candidate = SequentialCandidate( args )
            candidate.report()
    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "For help use --help"
        return 2

if __name__ == "__main__":
    sys.exit( main() )

