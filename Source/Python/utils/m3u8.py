#!/usr/bin/env python

__author__    = 'Oleksandr Paraska (olek@keyos.com)'
__copyright__ = 'Copyright 2015 BuyDRM.'

import os
import os.path as path
import uuid
import struct
import shutil
from Crypto.Cipher import AES
from Crypto.Util import Counter


DRM_TAG = "EXT_X_DXDRM"
DRM_INFO_TAG = "EXT_X_DXDRMINFO"
EXTINF = "#EXTINF"
EXTM3U = "#EXTM3U"

def getLines(string):
    return filter(
        lambda v: v, map(
            lambda s: s.strip(), string.split('\n')))

class HLSPlaylist:
    """A class for managing HLS M3U8 playlists"""
    playlistLines = []
    encryptedPlaylistLines = []
    segments = []
    def __init__(self, playlistsPath):
        self.playlistName = path.basename(playlistsPath)
        self.playlistPath = path.dirname(playlistsPath)
        with open(playlistsPath) as f:
            self.playlistLines = f.readlines()

    def parse(self, playlistsString):
        for line in self.playlistLines:
            line = line.strip()

            if line.startswith(EXTINF):
                duration, title = line.replace(protocol.extinf + ':', '').split(',')
                segments.extend = {'duration': float(duration), 'title': remove_quotes(title)}

    def addDiscretixPRHeader(self, kid, prHeader):
        self.encryptedPlaylistLines.insert(1, DRM_TAG + ":MECHANISM=PLAYREADY,VERSION=3.0\n")
        self.encryptedPlaylistLines.insert(2, DRM_INFO_TAG + ":HEADER=\"" + prHeader.encode('base64').replace('\n', '') + "\",KEYREF=\"x-keyref://playready/" + kid + "\"\n")

    def protectSegments(self, encryption_key, kid, output_path):
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        for i in range(0, len(self.playlistLines)):
            line = self.playlistLines[i]
            if line.startswith(EXTM3U):
                self.encryptedPlaylistLines = [line] + self.encryptedPlaylistLines
                continue
            self.encryptedPlaylistLines.extend(line)
            if line.startswith(EXTINF):
                i = i + 1
                line = self.playlistLines[i].strip()
                dirName = path.join(output_path, path.dirname(line))
                if not os.path.exists(dirName):
                    os.makedirs(path.join(output_path, dirName))
                with open(line, 'rb') as input_file, open(path.join(output_path, line), 'wb') as output_file:
                    IV = self.encryptFile(encryption_key, input_file, output_file)
                print IV
                self.encryptedPlaylistLines.extend("#EXT_X_KEY:METHOD:AES-128-CTR,IV=0x" + uuid.UUID(int=IV).hex + ",URI=\"x-keyref://playready?KID=" + kid + "\"\n")

    def envelopeProtectSegments(self, encryption_key, kid, output_path, prHeader):
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        for i in range(0, len(self.playlistLines)):
            line = self.playlistLines[i]
            if line.startswith(EXTINF):
                i = i + 1
                line = self.playlistLines[i].strip()
                dirName = path.join(output_path, path.dirname(line))
                if not os.path.exists(dirName):
                    os.makedirs(path.join(output_path, dirName))
                with open(path.join(self.playlistPath + "\\", line), 'rb') as input_file, open(path.join(output_path, line), 'wb') as output_file:
                    IV = self.envelopeEncryptFile(encryption_key, input_file, output_file, prHeader)
        shutil.copyfile(path.join(self.playlistPath, self.playlistName), path.join(output_path, self.playlistName))


    def encryptFile(self, encryption_key, input_file, output_file):
        # AES-128 CTR encrypt
        print "Encrypting " + input_file.name
        IV = uuid.uuid4().int & ((1 << 64) - 1) << 64
        ctr = Counter.new(128, initial_value = int(IV))
        key = uuid.UUID(encryption_key).bytes
        cipher = AES.new(key, AES.MODE_CTR, counter = ctr)
        finished = False
        while not finished:
            chunk = input_file.read(1024 * AES.block_size)
            if len(chunk) == 0:
                finished = True
            output_file.write(cipher.encrypt(chunk))
        return IV

    def envelopeEncryptFile(self, encryption_key, input_file, output_file, prHeader):
        # AES-128 CTR encrypt
        print "Protecting " + input_file.name
        ivBase = uuid.uuid4().bytes[0:8]
#        ctr = Counter.new(128, initial_value = int(iv))
        ctr = Counter.new(64, prefix=ivBase, initial_value=0, little_endian=False)
        key = uuid.UUID(encryption_key).bytes
        cipher = AES.new(key, AES.MODE_CTR, counter = ctr)

        original_file_name = input_file.name.encode('UTF-16LE')
        output_file.write(b'\x50\x52\x45\x07')                           # File signature. Constant
        output_file.write(struct.pack('l', len(prHeader) + len(original_file_name) + 66)) # Total header size
        output_file.write(struct.pack('l', len(prHeader) + len(original_file_name) + 66)) # Offset to encrypted data
        output_file.write(b'\x02\x00')                               # Format version
        output_file.write(b'\x01\x00')                               # Minimum compatibility version
        output_file.write(b'\x02\x00\x00\x00')                           # Cypher type
#        output_file.write(b'\x01\x02\x03\x04\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')                                   # Cypher data
        output_file.write(ivBase[::-1])                                   # Cypher data (base counter, aka prefix)
        output_file.write(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        output_file.write(struct.pack('h', len(original_file_name)))                      # Original filename length
        output_file.write(struct.pack('l', len(prHeader) + 12))                        # PR header length
        output_file.write(bytearray(original_file_name))                           # Original filename

        # PR header object
        output_file.write(struct.pack('l', len(prHeader) + 12))                        # PR header size
        output_file.write(b'\x01\x00')                                          # Number of PR records
        output_file.write(b'\x01\x00')                                          # PR record type (RM header)
        output_file.write(struct.pack('l', len(prHeader)))                        # PR header length
        output_file.write(bytearray(prHeader))                             # PR header
        output_file.write(b'\x00\x00\x00\x00')                           # Length of custom attributes

        finished = False
        while not finished:
            chunk = input_file.read(1024 * AES.block_size)
            if len(chunk) == 0:
                finished = True
            if len(chunk) < AES.block_size:
                chunk = self._pad(chunk)
            output_file.write(cipher.encrypt(chunk))
        return 0

    def _pad(self, s):
      return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def storeEncrypted(self, output_path):
        with open(path.join(output_path, self.playlistName), 'wb') as output_file:
            for line in self.encryptedPlaylistLines:
                output_file.write(line)

