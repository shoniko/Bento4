#!/usr/bin/env python


import uuid
import binascii

def main():
  print "test"
  #u = uuid.uuid4();
  u = uuid.UUID('65f9d43a-09aa-4d11-a087-8730ec11ead5');
  print str(uuid.UUID(bytes = u.bytes))
  print str(uuid.UUID(bytes = u.bytes_le))
  print u.bytes.encode('base64')
  print u.bytes_le.encode('base64')
  
###########################

if __name__ == '__main__':
  try:
    main()
  except Exception, err:
    if Options.debug:
      raise
    else:
      PrintErrorAndExit('ERROR: %s\n' % str(err))