#!/usr/bin/env python

__author__    = 'Oleksandr Paraska (olek@keyos.com)'
__copyright__ = 'Copyright 2015 BuyDRM.'

###
# NOTE: this script needs Bento4 command line binaries to run
# You must place the 'mp42ts'
# in a directory named 'bin/<platform>' at the same level as where
# this script is.
# <platform> depends on the platform you're running on:
# Mac OSX   --> platform = macosx
# Linux x86 --> platform = linux-x86
# Windows   --> platform = win32

from optparse import OptionParser
import keyos
import m3u8
import uuid
import base64
from mp4utils import *
from subprocess import check_output, CalledProcessError

# setup main options
VERSION = "1.0.0"
SCRIPT_PATH = path.abspath(path.dirname(__file__))
sys.path += [SCRIPT_PATH]

TempFiles = []

def main():
    # parse options
    global Options
    parser = OptionParser(usage="%prog [options] <keyos-user-key> <input-m3u8-file> <output_dir>",
                          description="""<input-m3u8-file> is the path to a source HLS plalist file. 
                                      <output_dir> - directory to write protected files to.\n
                                      <keyos-user-key> - your user key from keyos system.\n"""
                                      """Version """ + VERSION)
    parser.add_option('-v', '--verbose', dest="verbose", action='store_true', default=False,
                      help="Be verbose")
    parser.add_option('-d', '--debug', dest="debug", action='store_true', default=True,
                      help="Print out debugging information")
    (options, args) = parser.parse_args()
    Options = options
    if len(args) == 0:
        parser.print_help()
        sys.exit(1)
    keyos_user_key = args[0]
    playlist = m3u8.HLSPlaylist(args[1])

    encryption_key, prHeader, contentId = keyos.GetKeyosKey(keyos_user_key)
    kid_hex, key_hex = encryption_key.split(':')
    kid = uuid.UUID(kid_hex)
#    playlist.addEnvivioPRHeader(base64.b64encode(kid.bytes), prHeader)
    playlist.envelopeProtectSegments(key_hex, base64.b64encode(kid.bytes), args[2], prHeader)

###########################
if __name__ == '__main__':
    try:
        main()
    except Exception, err:
        if Options.debug:
            raise
        else:
            PrintErrorAndExit('ERROR: %s\n' % str(err))
    finally:
        for f in TempFiles:
            os.unlink(f)
