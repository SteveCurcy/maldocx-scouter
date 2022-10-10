#!/usr/bin/python
# coding = utf-8
#
# tc_doc_log.py
# eBPF application that parses HTTP response packets
# and extracts (and prints on screen) the document file
# contained in the Response Stream.
#
# eBPF program tc_doc_log.py is used as traffic-controler attached to veth (if it can) interface.
# Only packets of type ip and tcp containing document are
# returned to userspace, others passed directly.
#
# Python script uses bcc BPF Compiler Collection by
# iovisor (https://github.com/iovisor/bcc) and prints on stdout the files' information
# and statistic status.
#
# Copyright (c) Steve Curcy
# October 2022
# Licensed under the GPL, Version 3.0 (the "License")

from bcc import BPF
import ctypes as ct
import pyroute2
import socket
import os
import re
import pandas as pd
import joblib
import argparse

SIGNATURE_LOCAL_FILE_HEADER = 0x04034b50
SIGNATURE_CENTRAL_DIRECTORY = 0x02014b50

verbose = False
dev = None
is_docx = False
dt_model = None
sessions = None
# file's status
flags = 0
cont_sz = 0
exec_sz = 0
media_sz = 0
rest = 0


# find the first vitual eth
def auto_get_eth():
    global dev
    p = os.popen("ip a")
    search_obj = re.search(r'veth[a-z0-9]+', p.read())
    p.close()
    if search_obj:
        dev = search_obj.group()
    else:
        print("*** No container is running, default interface (ens33) will be used.")
        # exit(0)
        dev = "ens33"


def print_skb_event(cpu, data, size):
    global cont_sz, exec_sz, media_sz, rest, sessions, is_docx, dt_model, verbose
    raw_sz = size - ct.sizeof(ct.c_uint64)

    class SkbEvent(ct.Structure):
        _fields_ = [("offset", ct.c_uint32),
                    ("real_len", ct.c_uint32),
                    ("raw", ct.c_ubyte * raw_sz)]

    # get the Ctype raw data in bytes and get the properties
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    raw_data = bytes(bytearray(skb_event.raw))
    offset = skb_event.offset  # payload offset
    length = skb_event.real_len  # true payload length
    sig, fsz, csz, esz = 0, 0, 0, 0
    suffix = None

    # now we only consider one HTTP intact packet
    if rest:
        if length - offset < rest:
            rest -= (length - offset)
            return
        else:
            offset += rest
            rest = 0
    while offset < length:
        # cope with the header
        sig = int.from_bytes(raw_data[offset: offset + 4], 'little')
        if sig != SIGNATURE_LOCAL_FILE_HEADER:
            break
        csz = int.from_bytes(raw_data[offset + 18: offset + 22], 'little')
        fsz = int.from_bytes(raw_data[offset + 26: offset + 28], 'little')
        esz = int.from_bytes(raw_data[offset + 28: offset + 30], 'little')
        offset += 30

        # cope with the file name
        cont_sz += csz

        # check if this file is document, the DOCX file is a zip file with a file named "[Content_Types].xml"
        def check() -> bool:
            if raw_data[offset + 1] == 67 and raw_data[offset + 2] == 111 and raw_data[offset + 3] == 110 \
                    and raw_data[offset + 4] == 116 and raw_data[offset + 5] == 101 and raw_data[offset + 6] == 110 \
                    and raw_data[offset + 7] == 116 and raw_data[offset + 8] == 95 and raw_data[offset + 2] == 84:
                return True
            else:
                return False

        if not is_docx and fsz == 19 and check():
            is_docx = True
        if verbose:
            print(raw_data[offset: offset + fsz].decode('utf-8'), "({} B)".format(csz))
        #if fsz >= 5:
        # suffix = raw_data[offset + fsz - 4: offset + fsz].decode('utf-8').lower()
        # if suffix == '.bin':
        #     exec_sz += csz
        # if suffix == '.jpg' or suffix == '.png' or suffix == '.wmf' or suffix == '.svg' or suffix == 'jpeg':
        #     media_sz += csz
        last = raw_data[offset + fsz - 1]
        last = last + 32 if 65 <= last <= 90 else last
        if last == 110:  # n
            exec_sz += csz
        elif last == 103 or last == 102:  # g or f
            media_sz += csz
        offset += fsz

        # cope with the last part
        if length - offset < esz + csz:
            rest = esz + csz - (length - offset)
            break
        offset += esz + csz

    # cope with the whole file
    if sig == SIGNATURE_CENTRAL_DIRECTORY:
        ip_src = int.from_bytes(raw_data[26:30], 'big')
        ip_dst = int.from_bytes(raw_data[30:34], 'big')
        port_src = int.from_bytes(raw_data[34:36], 'big')
        port_dst = int.from_bytes(raw_data[36:38], 'big')
        current_key = sessions.Key(ip_src, ip_dst, port_src, port_dst)

        if is_docx:  # only the document info will be printed
            if verbose:
                print("[content size: {} B][executive ratio: {}][media ratio: {}]".format(cont_sz, exec_sz / cont_sz,
                                                                                          media_sz / cont_sz))
            print("[{}.{}.{}.{}:{} -> {}.{}.{}.{}:{}]".format((ip_src >> 24 & 0xff), (ip_src >> 16 & 0xff),
                                                              (ip_src >> 8 & 0xff), (ip_src & 0xff), port_src,
                                                              (ip_dst >> 24 & 0xff), (ip_dst >> 16 & 0xff),
                                                              (ip_dst >> 8 & 0xff), (ip_dst & 0xff), port_dst))
            new_row = pd.DataFrame([[cont_sz, exec_sz, media_sz], ], columns=["fsize", "exec_ratio", "media_ratio"],
                                   dtype=float)
            print("[property: {}]".format("suspicious" if dt_model.predict(new_row) == [1] else "benign"))
        # delete this item from the BPF MAP
        if current_key in sessions:
            del sessions[current_key]
        # clear the variables and prepare the next file parsing
        cont_sz, exec_sz, media_sz, rest, is_docx = 0, 0, 0, 0, False


def clear_clsact():
    # delete the original discipline
    p = os.popen("sudo tc -s qdisc ls dev {}".format(dev))
    search_obj = re.search(r'clsact', p.read())
    p.close()
    if search_obj:
        os.system("tc filter del dev {} egress".format(dev))
        os.system("tc qdisc del dev {} clsact".format(dev))


dt_model = joblib.load('decision-tree.model')
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="Print the details of the document. This option will bring a lot of time "
                                            "cost and is not recommended.", action="store_true")
parser.add_argument('-i', '--interface', help="Specify a interface you want to monitor, container's veth or ens33 "
                                              "will be the default choice.", default=None)
args = parser.parse_args()
verbose = args.verbose
if not args.interface:
    auto_get_eth()
else:
    dev = args.interface
try:
    b = BPF(src_file="tc_doc_log.c")
    fn = b.load_func("tc_check_docx", BPF.SCHED_CLS)
    ipr = pyroute2.IPRoute()
    ifd = ipr.link_lookup(ifname=dev)[0]

    clear_clsact()

    ipr.tc("add", "clsact", ifd)
    ipr.tc("add-filter", "bpf", ifd, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff2", classid=1, direct_action=True)

    b["skb_events"].open_perf_buffer(print_skb_event, page_cnt=16)
    sessions = b['sessions']
    print("scouter: tc attach to dev [{}].\n".format(dev))
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
finally:
    clear_clsact()
    print("\nscouter: tc dettach from dev [{}].".format(dev))
