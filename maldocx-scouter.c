#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#define bpf_ntohs(A) ((((u16)(A) & 0xff00) >> 8) | \
                            (((u16)(A) & 0x00ff) << 8))
#define bpf_ntohl(A) ((((u32)(A) & 0xff000000) >> 24) | \
                            (((u32)(A) & 0x00ff0000) >> 8) | \
                            (((u32)(A) & 0x0000ff00) << 8) | \
                            (((u32)(A) & 0x000000ff) << 24))

#define ETH_HLEN 14
#define SIGNATURE_LOCAL_FILE_HEADER   0x04034b50

// for HTTP, a port can be bound with just one socket and represent one session,
// so, I change the Key with only one member which is the dst_port. But for alignment,
// I reserve a dummy field for 4B alignment.
struct Key {
    u16 dummy;      //no meaning
    u16 dst_port;   //destination port
};

struct Leaf {
    u32 offset;     // offset to the data beginning
    u32 real_len;   // real length of the valid payload
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf);
BPF_PERF_OUTPUT(skb_events);

/*
 * eBPF program.
 * Filter IP and TCP packets, having payload not empty
 * and containing "HTTP" as first bytes of payload of the HTTP Response.
 * AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
 * this means belonging to the same "session"
 * We find a response which contains docx file and return it to user space.
 * And the data flows is created by docker httpd. For convenience, We only
 * ponder the specified situation and do the experiment.
 */
int tc_check_docx(struct __sk_buff *skb) {
    // meta data of the socket buffer (16 B)
    u8 *cursor = 0;
    void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	// essential structures (52 B)
    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(*eth);
    struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
    struct Key  key = {0, 0};
    struct Leaf leaf = {0, 0};

    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP || iph->ihl != 5)
        return TC_ACT_OK;
    if (bpf_ntohs(tcph->source) != PORT) return TC_ACT_OK;
    // fill the key structure
    key.dst_port = bpf_ntohs(tcph->dest);

    // to record the payload status (12 B)
    u32 payload_offset = ETH_HLEN + 20 + (tcph->doff << 2);
    leaf.real_len = bpf_ntohs(iph->tot_len) + ETH_HLEN;
    u32 signature;

    // check if it's a HTTP response (24 B)
    if (leaf.real_len - payload_offset < 261) return TC_ACT_OK;
    char p[20];  // variable for string storage
    int i = 0;
    for (i = 0; i < 4; i++) {
        p[i] = load_byte(skb, payload_offset + i);
    }
    // check if this is the first flow of the session (8 B)
    struct Leaf *lookup_leaf = sessions.lookup(&key);

    if (!lookup_leaf) {
        if ((p[0] != 'H') || (p[1] != 'T') || (p[2] != 'T') || (p[3] != 'P')) return TC_ACT_OK;
        // skip the HTTP header's items one by one accurately.
        payload_offset += 196;   // skip "HTTP/1.1 200 OK\r\n" To "Content-Length: "
        // we only notice our environment which is a docker httpd container.
        // we find the CRLF of the Content-Length and skip it.
        if (load_byte(skb, payload_offset + 5) == '\r') payload_offset += 7;        // 10,000 B
        else if (load_byte(skb, payload_offset + 6) == '\r') payload_offset += 8;   // 100,000 B
        else if (load_byte(skb, payload_offset + 7) == '\r') payload_offset += 9;   // 1,000,000 B
        else if (load_byte(skb, payload_offset + 8) == '\r') payload_offset += 10;  // 10,000,000 B
        else if (load_byte(skb, payload_offset + 9) == '\r') payload_offset += 11;  // 100,000,000 B
        if (load_byte(skb, payload_offset) == 'K') payload_offset += 58;
        else payload_offset += 2;
        signature = load_word(skb, payload_offset);
        if (bpf_ntohl(signature) != SIGNATURE_LOCAL_FILE_HEADER) return TC_ACT_OK;  // not a zip file
        sessions.update(&key, &leaf);
    }

    leaf.offset = payload_offset;
    skb_events.perf_submit_skb(skb, skb->len, &leaf, sizeof(leaf));

    return TC_ACT_OK;
}