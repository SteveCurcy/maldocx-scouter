#!/usr/bin/python

from bcc import BPF
import ctypes as ct
import pyroute2
import socket
import os
import re

dev = ""
flags = 0
file_sz = 0
exec_sz = 0
media_sz = 0
rest = 0
is_res = False

# find the first vitual eth
p = os.popen("ip a")
search_obj = re.search(r'veth[a-z0-9]+', p.read())
p.close()
if search_obj:
    dev = search_obj.group()
else:
    print("*** No container is running.")
    # exit(0)
    dev = "ens33"


def print_skb_event(cpu, data, size):
    global file_sz, exec_sz, media_sz, rest, is_res
    raw_sz = size - ct.sizeof(ct.c_uint32)

    class Leaf(ct.Structure):
        _fields_ = [("file_sz", ct.c_uint32),
                    ("exec_sz", ct.c_uint32),
                    ("media_sz", ct.c_uint32),
                    ("rest", ct.c_uint32)]

    class SkbEvent(ct.Structure):
        _fields_ = [("leaf", Leaf),
        # _fields_ = [("magic", ct.c_ubyte),
                    ("raw", ct.c_ubyte * raw_sz)]

    # get the Ctype raw data in bytes.
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    print("[file size: {} B][executive size: {} B][media size: {} B]".format(skb_event.leaf.file_sz, skb_event.leaf.exec_sz, skb_event.leaf.media_sz))
    # print (skb_event.magic)


def clear_clsact():
    # delete the original discipline
    p = os.popen("sudo tc -s qdisc ls dev {}".format(dev))
    search_obj = re.search(r'clsact', p.read())
    p.close()
    if search_obj:
        os.system("tc filter del dev {} egress".format(dev))
        os.system("tc qdisc del dev {} clsact".format(dev))


try:
    b = BPF(src_file="tc_doc_log.c")
    fn = b.load_func("tc_check_docx", BPF.SCHED_CLS)
    ipr = pyroute2.IPRoute()
    ifd = ipr.link_lookup(ifname=dev)[0]

    clear_clsact()

    ipr.tc("add", "clsact", ifd)
    ipr.tc("add-filter", "bpf", ifd, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff2", classid=1, direct_action=True)

    b["skb_events"].open_perf_buffer(print_skb_event)
    print("tc attach to dev [{}].".format(dev))
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    clear_clsact()
    print("tc dettach from dev [{}].".format(dev))
finally:
    pass
    # if "me" in locals(): ipr.link("del", index=me)
