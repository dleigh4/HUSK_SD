# include <linux/init.h>
# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/netfilter.h>
# include <linux/netfilter_ipv4.h>
# include <linux/ip.h>
# include <linux/tcp.h>
# include <linux/udp.h>
# include <types.h>
# include <stdio.h>
# include <sys/ipc.h>
# include <sys/msg.h>

// Message queue datastructure (HUSK)
typedef struct husk_message { 
    long mesg_type; 
    __u32 dstaddr; 
	__u32 srcaddr;
	__u16 dstport;
	__u16 srcport;
	__u8 proto;
} message; 

static struct nf_hook_ops *nfho = NULL;

static key_t key;
static __u32 msgsize;

static unsigned int husk_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	message husk_msg;
	int msgid;
	
	if (skb) {
		
		msgid = msgget(key, 0666 | IPC_CREAT);
		iph = ip_hdr(skb);
		husk_msg.dstaddr = iph->daddr;
		husk_msg.srcaddr = iph->saddr;
		husk_msg.proto = iph->protocol;
		husk_msg.mesg_type = 1;
		
		if (iph->protocol == IPPROTO_UDP) {
			udph = udp_hdr(skb);
			husk_msg.dstport = udph->dest;
			husk_msg.srcport = udph->source;
			
			msgsnd(msgid, &message, msgsize, 0);
		}
		
		else if (iph->protocol == IPPROTO_TCP) {
			tcph = tcp_hdr(skb);
			husk_msg.dstport = tcph->dest;
			husk_msg.srcport = tcph->source;
			
			msgsnd(msgid, &message, msgsize, 0);
		}
	
	}
	
	return NF_ACCEPT;
}


static int __init husk_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nfho->hook 	= (nf_hookfn*)husk_hook;		/* hook function */
	nfho->hooknum 	= NF_IP_FORWARD;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	key = ftok("HUSK_QUEUE", 1);
	
	nf_register_net_hook(&init_net, nfho);
}

static void __exit husk_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(husk_init);
module_exit(husk_exit);

