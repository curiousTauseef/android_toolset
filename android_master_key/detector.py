#!/usr/bin/env python

# -*- coding: utf-8 -*-

#
# Copyright (c) yajin <yajin@vm-kernel.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys
import struct
import os

#1.http://bluebox.com/corporate-blog/bluebox-uncovers-android-master-key/
#2.http://blog.sina.com.cn/s/blog_be6dacae0101bksm.html
#3.http://www.saurik.com/id/18/
#4.http://www.saurik.com/id/19

def usage():
    print "[usage] python detector.py apkfile"

def die(msg):
    print "[Die]: ",
    print msg
    sys.exit(-1)

def view_apk(javaview, fd, n_cdr, o_cdr, tabcnt):
    c_o_cdr = o_cdr

    for i in xrange(n_cdr):
        fd.seek(c_o_cdr)

        fd.seek(c_o_cdr + 28)
        filename_length = struct.unpack("<H", fd.read(2))[0]

        fd.seek(c_o_cdr + 30)
        extra_field_length = struct.unpack("<H", fd.read(2))[0]

        fd.seek(c_o_cdr + 32)
        filecomment_length = struct.unpack("<H", fd.read(2))[0]

        if (extra_field_length >= 0x8000) and javaview:
            extra_field_length = 0

        if (filecomment_length >= 0x8000) and javaview:
            filecomment_length = 0

        fd.seek(c_o_cdr + 46)
        file_name = fd.read(filename_length)

        for j in xrange(tabcnt):
            print "\t",

        print "[" + str(i) + "]: " + file_name

        c_o_cdr += 46 + filename_length + filecomment_length + extra_field_length


def parse_apk_file(fd, file_size):

    local_file_header_offsets = []
    file_names = []
    file_names_length = []

    #1. find the eocdr
    for i in reversed(xrange(file_size - 4)):
        fd.seek(i)
        eocdr = struct.unpack("<i", fd.read(4))[0]
        # print hex(eocdr)
        if int(eocdr) == 0x06054b50:
            break

    #should be smaller enough
    if i < 32:
        die ("Input file is not a valid apk")

    #2. parse eocdr
    fd.seek(i + 10)
    n_cdr = struct.unpack("<H", fd.read(2))[0]
    fd.seek(i + 16)
    o_cdr = struct.unpack("<i", fd.read(4))[0]


    if (o_cdr >= file_size):
        die ("Corrupted apk file. Invalid cdr offset (" + hex(o_cdr) + ")")

    print "Number of CDRs: [" + str(n_cdr) +"]"

    #3. loop over cdr
    c_o_cdr = o_cdr

    is_exploit3 = False
    is_exploit1 = False
    is_exploit4 = False

    for i in xrange(n_cdr):
        # print hex(c_o_cdr)

        fd.seek(c_o_cdr)
        cdr_header = struct.unpack("<I", fd.read(4))[0]
        if (int(cdr_header) != 0x02014b50):
            die ("Corrupted apk file. Invalid cdr header (" + hex(cdr_header) + ")")

        fd.seek(c_o_cdr + 28)
        filename_length = struct.unpack("<H", fd.read(2))[0]

        fd.seek(c_o_cdr + 30)
        extra_field_length = struct.unpack("<H", fd.read(2))[0]

        fd.seek(c_o_cdr + 32)
        filecomment_length = struct.unpack("<H", fd.read(2))[0]

        fd.seek(c_o_cdr + 42)
        local_file_header_offset = struct.unpack("<I", fd.read(4))[0]

        local_file_header_offsets.append(local_file_header_offset)

        if (extra_field_length >= 0x8000):
            is_exploit3 = True
            break

        if (filecomment_length >= 0x8000):
            is_exploit3 = True
            break

        fd.seek(c_o_cdr + 46)
        file_name = fd.read(filename_length)

        if (file_name in file_names):
            is_exploit1 = True
            break

        file_names.append(file_name)
        file_names_length.append(filename_length)

        c_o_cdr += 46 + filename_length + filecomment_length + extra_field_length

    if is_exploit1:
        print ("\t--> Exploit 1 detected")
        print "\t\tDuplicated file : " + file_name
        exit(-1)

    if is_exploit3:
        print ("\t--> Exploit 3 detected")
        print "\t[*] View apk file in Java "
        view_apk(True, fd, n_cdr, o_cdr, 2)
        print "\t[*] View apk file in native "
        view_apk(False, fd, n_cdr, o_cdr, 2)
        exit(-1)

    for local_file_header_offset in local_file_header_offsets:
        index = local_file_header_offsets.index(local_file_header_offset)

        fd.seek(local_file_header_offset)
        ldr_header = struct.unpack("<I", fd.read(4))[0]

        if (int(ldr_header) != 0x4034b50):
            die ("Corrupted apk file. Invalid local file header (" + hex(ldr_header) + ")")

        fd.seek(local_file_header_offset + 26)

        filename_length = struct.unpack("<H", fd.read(2))[0]

        if (file_names_length[index] != filename_length):
            is_exploit4 = True
            print ("\t--> Exploit 4 detected: [" + file_names[index] + "].")
            print "\t\t--> Java: (" + str(file_names_length[index]) + ")"
            print "\t\t--> C++: (" + str(filename_length) + ")"
            break


        fd.seek(local_file_header_offset + 28)
        extra_field_length = struct.unpack("<H", fd.read(2))[0]

        if (extra_field_length >= 0x8000):
            print ("\t--> Exploit 2 detected")
            break

    return False


def main():
    if len(sys.argv) != 2:
        usage()
        exit(-1)

    try:
        fd = open(sys.argv[1], "rb")
    except:
        die("Can't read supplied filename: (" + sys.argv[1] + ")")

    file_size = os.path.getsize(sys.argv[1])
    parse_apk_file(fd, file_size)

if __name__ == '__main__':
    main()