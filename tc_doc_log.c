#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include "ebpf_string.c"

#define bpf_ntohs(A) ((((u16)(A) & 0xff00) >> 8) | \
                            (((u16)(A) & 0x00ff) << 8))
#define bpf_ntohl(A) ((((u32)(A) & 0xff000000) >> 24) | \
                            (((u32)(A) & 0x00ff0000) >> 8) | \
                            (((u32)(A) & 0x0000ff00) << 8) | \
                            (((u32)(A) & 0x000000ff) << 24))
#define ETH_HLEN 14
#define MAX_LOOP 200
#define SIGNATURE_LOCAL_FILE_HEADER   0x04034b50
#define SIGNATURE_CENTRAL_DIRECTORY   0x02014b50

struct Key {
    u32 src_ip;    //source ip
    u32 dst_ip;    //destination ip
    u16 src_port;  //source port
    u16 dst_port;  //destination port
};

struct Leaf {
    u32 offset;     // offset to the data beginning
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf, 1024);
BPF_PERF_OUTPUT(skb_events);

/*
 * eBPF program.
 * Filter IP and TCP packets, having payload not empty
 * and containing "HTTP" as first bytes of payload of the HTTP Response.
 * AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
 * this means belonging to the same "session"
 */
int tc_check_docx(struct __sk_buff *skb) {
    // meta data of the socket buffer (16 B)
    void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	// essential structures (52 B)
    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(*eth);
    struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
    struct Key  key;
    struct Leaf leaf = {
            .file_sz = 0,
            .exec_sz = 0,
            .media_sz = 0,
            .rest = 0
    };

    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP || iph->ihl != 5)
        return TC_ACT_OK;
    if (bpf_ntohs(tcph->source) != 80) return TC_ACT_OK;
    // fill the key structure
    key.dst_ip = iph->daddr;
    key.src_ip = iph->saddr;
    key.dst_port = bpf_ntohs(tcph->dest);
    key.src_port = bpf_ntohs(tcph->source);

    // to record the payload status ()
    u32 payload_offset = ETH_HLEN + 20 + (tcph->doff << 2);
    u32 payload_length = iph->tot_len + ETH_HLEN;
    u32 signature, cmp_sz;
    u16 fname_sz, extra_sz;

    // check if it's a HTTP response (24 B)
    if (payload_length - payload_offset < 261) return TC_ACT_OK;
    char p[20];  // variable for string storage
    int i = 0;
    for (i = 0; i < 4; i++) {
        p[i] = load_byte(skb, payload_offset + i);
    }
    // check if this is the first flow of the session (8 B)
    struct Leaf *lookup_leaf = sessions.lookup(&key);

    if (!lookup_leaf) {
        if ((p[0] != 'H') || (p[1] != 'T') || (p[2] != 'T') || (p[3] != 'P')) return TC_ACT_OK;
        // lookup_leaf = &leaf;
        // try to skip the HTTP header
        payload_offset += 205;
    } else {
        // have mark that session, and we should check if there are fragments.
        if (payload_length - payload_offset < lookup_leaf->rest) {
            // this flow is not enough
            lookup_leaf->rest -= (payload_length - payload_offset);
            return TC_ACT_OK;
        } else {
            // skip the rest of fragment
            payload_offset += lookup_leaf->rest;
            lookup_leaf->rest = 0;
        }
    }

    // we find the first of the local file header
    for (i = 0; i < MAX_LOOP; i++) {
        if (payload_offset + i > payload_length) return TC_ACT_OK;
        signature = bpf_ntohl(load_word(skb, payload_offset + i));
//        bpf_probe_read_kernel(&signature, sizeof(signature), data + payload_offset + i);
        if (signature == SIGNATURE_LOCAL_FILE_HEADER || signature == SIGNATURE_CENTRAL_DIRECTORY) break;
    }

    if (i == MAX_LOOP) {
        // there is no local file header, delete the map info if there is an item
        if (lookup_leaf) sessions.delete(&key);
        return TC_ACT_OK;
    }
    payload_offset += i;
    for (i = 0; i < MAX_LOOP; i++) {
        if (payload_offset + 30 > payload_length) break; // assure the bound safety
        signature = bpf_ntohl(load_word(skb, payload_offset));
        if (signature == SIGNATURE_CENTRAL_DIRECTORY) {
            bpf_probe_read_kernel(&leaf, sizeof(leaf), lookup_leaf);
            // reach the bound of the Central Directory and we should submit the document info and return.
            sessions.delete(&key);
            skb_events.perf_submit_skb(skb, skb->len, &leaf, sizeof(leaf));
            return TC_ACT_OK;
        }
        /* local file header
         * +----------------------------------+----------------+-----------------+
         * |          signature(4B)           | Version(2B)    | GPB flag(2B)    |
         * +---------------+------------------+----------------+-----------------+
         * | Method(2B)    |  LastModTime(2B) |LastModDate(2B) |
         * +---------------+------------------+----------------+-----------------+
         * |           CRC-32(4B)             |       Compressed Size(4B)        |
         * +----------------------------------+----------------+-----------------+
         * |      Uncompressed Size(4B)       |FileNameLen(2B) |ExtraFieldLen(2B)|
         * +----------------------------------+----------------------------------+
         * |         File name (nB)           |           Extra field            |
         * +----------------------------------+----------------------------------+
         */
        // signature is the local file header, we extract the useful infos.
        cmp_sz = bpf_ntohl(load_word(skb, payload_offset + 18));
        fname_sz = bpf_htons(load_half(skb, payload_offset + 26));
        extra_sz = bpf_htons(load_half(skb, payload_offset + 28));
        payload_offset += 30;   // skip the header

        // check if there is a file named "[Content_Types].xml" in first flow.
        if (payload_offset + fname_sz > payload_length) break;
        if (!lookup_leaf && fname_sz != 19) break; // no content_type file there
        if (!lookup_leaf) {
            for (int j = 0; j < 19; j++) {
                p[j] = load_byte(skb, payload_offset + j);
            }
            if (p[0] != '[' || p[14] != ']' || p[1] != 'C' || p[15] != '.' || p[8] != '_' || p[9] != 'T' || p[16] != 'x') return TC_ACT_OK;
            // one local file header found. if not already present, insert into map <Key, Leaf>
            sessions.update(&key, &leaf);
            lookup_leaf = &leaf;
        }
        // get the suffix name of the file
        for (int j = 0; j < 4; j++) {
            p[j] = load_byte(skb, payload_offset + fname_sz - 4 + j);
            if ('A' <= p[j] && p[j] <= 'Z') p[j] = p[j] - 'A' + 'a';
        }
        payload_offset += fname_sz;
        // update the status info
        lookup_leaf->file_sz += cmp_sz;
#define is_equal4(STR, a, b, c, d) (STR[0] == a && STR[1] == b && STR[2] == c && STR[3] == d)
        if (is_equal4(p, '.', 'b', 'i', 'n')) lookup_leaf->exec_sz += cmp_sz;
        if (is_equal4(p, '.', 'j', 'p', 'g')) lookup_leaf->media_sz += cmp_sz;
        if (is_equal4(p, '.', 'p', 'n', 'g')) lookup_leaf->media_sz += cmp_sz;
        if (is_equal4(p, '.', 'w', 'm', 'f')) lookup_leaf->media_sz += cmp_sz;
        if (is_equal4(p, '.', 's', 'v', 'g')) lookup_leaf->media_sz += cmp_sz;
        if (is_equal4(p, 'j', 'p', 'e', 'g')) lookup_leaf->media_sz += cmp_sz;

        // check if there are fragments and handle it
        if (payload_offset + extra_sz + cmp_sz > payload_length) {
            lookup_leaf->rest = extra_sz + cmp_sz - (payload_length - payload_offset);
            break;
        }
        payload_offset += extra_sz + cmp_sz;
    }

    return TC_ACT_OK;
}