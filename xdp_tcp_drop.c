#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("drop_tcp")
int tcp_drop(struct xdp_md *ctx) {
   int ipsize = 0;

   void *data = (void *)(long)ctx->data;
   void *data_end = (void *)(long)ctx->data_end;

   struct ethhdr *eth = data;
   ipsize = sizeof(*eth);
   struct iphdr *ip = data + ipsize;
   ipsize += sizeof(struct iphdr);

   if (data + ipsize > data_end) {
     return XDP_PASS;
   }

   // Determine whether the packet is based on the TCP protocol 
   if (ip-> protocol == IPPROTO_TCP) {
      // Discard the packet 
     return XDP_DROP;
   }

   return XDP_PASS;
 }

 char _license[] SEC("license") = "GPL";
