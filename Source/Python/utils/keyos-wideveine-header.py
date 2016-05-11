#!/usr/bin/env python

__author__    = 'Oleksandr Paraska (olek@keyos.com)'
__copyright__ = 'Copyright 2015 NFA Group Inc. All rights reserved.'

from optparse import OptionParser
import shutil
from mp4utils import *
import keyos
import uuid
import tempfile


def main():

    # parse options
    parser = OptionParser(usage="%prog [options]",
                          description="Generate a Widevine PSSH header for given ContentID, KeyID")
    parser.add_option('-k', '--keyos-user-key', dest="keyos_user_key", help="BuyDRM KeyOS User Key")

    (options, args) = parser.parse_args()
    global Options
    Options = options

    options.encryption_key, options.playready_header, content_id = keyos.GetKeyosKey(options.keyos_user_key)
    kid_hex, key_hex = options.encryption_key.split(':')
    wvHeader = "provider:buydrmkeyos"
    wvHeader = wvHeader + "contentid:" + content_id;
    widevine_header = ComputeWidevineHeader(wvHeader, kid_hex, key_hex)
    print "Widevine PSSH (base64):"
    print widevine_header.encode('base64').replace('\n', '')

###########################
if __name__ == '__main__':
    try:
        main()
    except Exception, err:
        if Options.debug:
            raise
        else:
            PrintErrorAndExit('ERROR: %s\n' % str(err))