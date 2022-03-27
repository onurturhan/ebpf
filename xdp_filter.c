#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("prog")

int xdp_filter(struct xdp_md *ctx) {
  bpf_trace_printk("got a packet\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end) {
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) <= data_end) {
      if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
          if (udp->dest == ntohs(7999)) {
            bpf_trace_printk("udp port 7999\n");
            udp->dest = ntohs(7998);
          }
        }
      }
    }
  }
  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

