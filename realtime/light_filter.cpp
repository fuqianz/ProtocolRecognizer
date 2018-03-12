#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <time.h>
#include <vector>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#define SYMBOL_CNT 10

double mappings[SYMBOL_CNT + 1] = {-1,};
int symbol_cnt;

const double max_statistic = 1000000;
const int max_test_packets = 300;

/* flow struct */
struct flow
{
	unsigned int srcport;
	unsigned int srcip;
	unsigned int dstport;
	unsigned int dstip;
	unsigned int pcnt;
	int symbolcnts[SYMBOL_CNT];
	struct timeval ptime;
};

/*
 * the instructure for flow
 */
std::unordered_map<unsigned int, struct flow*> flow_info;
std::unordered_set<unsigned int> trusted_flows;
std::unordered_set<unsigned int> unrecognized_flows;
std::queue<struct flow*>* bufferQ;

int verified_flow;
int reference[] = { 23, 96714, 25852, 100444, 7564, 5, 19433 } ;
bool end;
bool finish;

std::vector<double> consumed_time;

/* read mappings */
int read_mappings(char* mapfilepath, double* maps)
{
	double left, right;
	char symbol[10];
	int cnt = 0;

	FILE* fp = fopen(mapfilepath, "r");	
	if (fp == NULL) 
	{
		printf("Error to open mapping file!\n");
		return 1;
	}
	
	while (fscanf(fp,"%lf,%lf;%s", &left, &right, symbol) != EOF)
	{
		maps[cnt ++] = left;
		printf("%lf,%lf;%s\n",left, right, symbol);
		if (cnt > SYMBOL_CNT  )
		{
			printf("Too many symbols!\n");
			return 1;
		}		
	}
	maps[cnt++] = right;
	symbol_cnt = cnt;	
	return 0;
}


double time_diff(struct timeval x , struct timeval y)
{
    double x_ms , y_ms , diff;
    x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
    y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
    diff = (double)y_ms - (double)x_ms;                     
    return diff;
}

void calculate_statistics(unsigned int key)
{

    double result = 0.0;
 
    for (int i = 0 ; i < symbol_cnt; i ++)
    {
        int x = flow_info[key]->symbolcnts[i];
        if (x == 0) x = 5;

        double t = (x - reference[i]);
        result += t*t/x;
    }
	
	if (result <= max_statistic)
	{
		trusted_flows.insert(key);
	}
	else
	{
		unrecognized_flows.insert(key);
	}
    return;
}

void* update_flow_info(void* args)
{
    finish = false;

	while (true && !end)
	{
		while(!bufferQ->empty()) {
        struct timeval before, after;

        gettimeofday(&before, NULL);

		struct flow* cflow = bufferQ->front();
		bufferQ->pop();
		unsigned int key = 0;
		if (cflow->srcport < cflow->dstport)
		{
			key = ((unsigned int)(cflow->srcip) * 59) ^ ((unsigned int)(cflow->dstip)) ^ ((unsigned int)cflow->srcport << 16) ^ (cflow->dstport);
		}
		else
		{
			key = ((unsigned int)(cflow->dstip) * 59) ^ ((unsigned int)(cflow->srcip)) ^ ((unsigned int)cflow->dstport << 16) ^ (cflow->srcport);
		}

		if (trusted_flows.find(key) != trusted_flows.end())
		{
			// sent to the system
			verified_flow ++;
			continue;	
		}

		if (unrecognized_flows.find(key) != unrecognized_flows.end())
		{
			// sent to high weight
			continue;	
		}

		// add current packet info to map, and upate the flow
		if (flow_info.find(key) != flow_info.end())
		{
			struct flow* lflow = flow_info[key];
			
			struct timeval vvp;
			timersub(&(cflow->ptime), &(lflow->ptime), &vvp);
	        double x = time_diff(lflow->ptime, cflow->ptime);	
			for (int i = 0 ; i < symbol_cnt; ++i)
			{
				if (x < mappings[i+1])
				{
					cflow->symbolcnts[i] ++;
				}
			}
			lflow->ptime = cflow->ptime;
	        lflow->pcnt ++; 
			free(cflow);
			
			if (lflow->pcnt >=  max_test_packets)
			{
                calculate_statistics(key);
                flow_info.erase(key); 
				//pthread_t tid;
				//int err = pthread_create(&tid, NULL, &calculate_statistics, &key);
				//if (err != 0)
				//{
				//	printf("create calculation thread error");
				//	return (void *)0;
				//}
			}	
		}	
		else
		{
			for (int i = 0 ; i < symbol_cnt; ++i)
			{
				cflow->symbolcnts[i] = 0;
			}
		
			flow_info[key] = cflow;	
		}

        gettimeofday(&after, NULL);
        printf("%lf\n", time_diff(before, after));        
        }
	}

    finish = true;

	return (void*) 0;
}


/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	//const struct sniff_ethernet *ethernet = NULL;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */

	int size_ip;

	/* define ethernet header */
	// ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
	//	printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	// determine protocol	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			break;
		case IPPROTO_UDP:
			return;
		case IPPROTO_ICMP:
			return;
		case IPPROTO_IP:
			return;
		default:
			return;
	}
	//printf("\nPacket number %d:", count);
	//printf(", Time: %ld , %ld", header->ts.tv_sec, header->ts.tv_usec);	

	count++;

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
	unsigned int sport = ntohs(tcp->th_sport);
	unsigned int dport = ntohs(tcp->th_dport);	
	
	//printf(", Src port: %d", sport);
	//printf(", Dst port: %d\n", dport);


	// assign a flow
	struct flow* newflow = (struct flow*)malloc(sizeof(struct flow));
	newflow->srcport = sport;
	newflow->dstport = dport;
	newflow->srcip = ip->ip_src.s_addr;
	newflow->dstip = ip->ip_dst.s_addr;
	newflow->pcnt = 1;
	newflow->ptime = header->ts;
	bufferQ->push(newflow);
    
	return;
}

int main(int argc, char **argv)
{


	char *dev = NULL;			/* capture device name */
	char *mapfilepath = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int t = 0;

	/* check for capture device name on command-line */
	if (argc == 3) {
		dev = argv[1];
		mapfilepath = argv[2];
	}
	else {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}

    // init some buffers
    bufferQ = new std::queue<struct flow*>();

	/* get mapping array */
	read_mappings(mapfilepath, mappings);
	//
	for (t = 0 ; t < 10 ; t ++)
	{
		printf("t = %.12lf\n", mappings[t]);
	}	
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n",100*max_test_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}


	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

    printf("111\n");
	// create a thread to handle all flow info
	pthread_t tid;
	int err = pthread_create(&tid, NULL, &update_flow_info, NULL);
	if (err != 0)
	{
		printf("error to create thread to update flow info!\n");
		return 0;
	}

    end = false;

	/* now we can set our callback function */
	pcap_loop(handle, 100*max_test_packets, got_packet, NULL);

    end = true;

    // output time
    printf("%d\n",(int) consumed_time.size());
    for (auto it = consumed_time.begin(); it != consumed_time.end(); ++it) 
    {
        printf("%lf\n", *it);
    }

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

    while(!finish);


	printf("\nCapture complete.\n");

	return 0;
}

