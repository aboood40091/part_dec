#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Wii Partition decryptor
# Version v0.1
# Copyright © 2011 delroth, 2016 AboodXD

# Heavily based on: http://blog.delroth.net/2011/06/reading-wii-discs-with-python/
# Thanks delroth!

"""part_dec.py: Converts Wii ISOs to decrypted partition files."""

print("Wii Partition decryptor v0.1")
print("(C) 2011 delroth, 2016 AboodXD")
print("")

import os, sys, time
from collections import namedtuple
from struct import unpack as up
from Crypto.Cipher import AES

if len(sys.argv) != 2:
    print("")
    print("Usage: python part_dec.py input(ISO)")
    print("")
    print("Exiting in 5 seconds...")
    time.sleep(5)
    sys.exit(1)

fp = open(sys.argv[1], 'rb')

PartEntry = namedtuple('PartEntry', 'offset type')
def read_part_entry(offset):
    fp.seek(offset)
    (data_offset, type) = up('>LL', fp.read(8))
    data_offset *= 4
    return PartEntry(data_offset, type)

VGEntry = namedtuple('VGEntry', 'part_count table_offset')
def read_vg_entry(offset):
    fp.seek(offset)
    (part_count, table_offset) = up('>LL', fp.read(8))
    table_offset *= 4
    return VGEntry(part_count, table_offset)

base_off = 0x40000
def read_part_table():
    vgs = {}
    for vg_num in range(4):
        vg_ent = read_vg_entry(base_off + (8 * vg_num))
        if vg_ent.part_count == 0:
            continue
        vgs[vg_num] = {}
        for part_num in range(vg_ent.part_count):
            off = vg_ent.table_offset + (8 * part_num)
            part = read_part_entry(off)
            vgs[vg_num][part_num] = part
    return vgs

Ticket = namedtuple('Ticket', 'enc_tit_key tit_id data_off data_len')

master_key = b'\xeb\xe4\x2a\x22\x5e\x85\x93\xe4\x48\xd9\xc5\x45\x73\x81\xaa\xf7' # Wii Common key

name = os.path.splitext(sys.argv[1])[0]

print('Python is slow, this is going to take a while... Please wait!')
print('')
time.sleep(5)

def read_cluster(idx, part, ticket, key):
    data_offset = part.offset + (ticket.data_off * 4)
    cluster_offset = data_offset + (idx * 0x8000)
    fp.seek(cluster_offset)
    data_enc = fp.read(0x8000)
    iv = data_enc[0x3D0:0x3E0]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(data_enc[0x400:])

for vg_num in range(4):
    vg_ent = read_vg_entry(base_off + (8 * vg_num))
    if vg_ent.part_count == 0:
        continue
    for part_num in range(vg_ent.part_count):
        part = read_part_table()[vg_num][part_num]
        fp.seek(part.offset)
        ticket = Ticket(*up('>447x16s13x16s204xLL', fp.read(704)))
        iv = ticket.tit_id[:0x8] + (b'\x00' * 8)
        aes = AES.new(master_key, AES.MODE_CBC, iv)
        key = aes.decrypt(ticket.enc_tit_key)

        nclusters = ticket.data_len * 4 // 0x8000

        out_fp = open(name + '_' + str(vg_num) + '_' + str(part_num) + '.bin', 'wb')

        for i in range(nclusters):
            print('%f%%' % (i * 100.0 / nclusters))
            out_fp.write(read_cluster(i, part, ticket, key))
        print('100.0%')
        print('')

print('Done!')
time.sleep(5)
