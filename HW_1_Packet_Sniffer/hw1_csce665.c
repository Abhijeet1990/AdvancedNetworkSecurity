
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <net/if.h>
#include <netinet/if_ether.h>
#include<sys/socket.h>
#include <pcap.h>

/***************LIST of FUNCTION Declarations*************************/
//prints both HTTP and FTP data
void PrintData (const unsigned char* , int);
//prints the TELNET data
void PrintTelnetData (const unsigned char* , int);
/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);
/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);
/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);
/*for processing the TCP packets*/
void dump_TCP_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len, char* protocol);
/*reasseble HTTP packets*/
void reassemble(const unsigned char* , int,char*,char*);
int i,j,count=0;
//this holds the source and destination ip address
struct sockaddr_in source,dest;
//this is the flag used to check the end of  a session in TELNET
int test = 1;

struct array
{
char x[20];
char y[20];
//char *payload;
};

int c =0;
/*for the assignment we are concerned with the TCP header rather than UDP...Telnet, FTP and HTTP are the protocol that mainly use TCP protocols*/

//This variables are initialized to be one. This is used to hold the current sequence number and the previous packet ACK number
int prev_ack=1,cur_seq=1; 


void dump_TCP_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len, char* protocol)
{
	
	int k=0;
	char sip[20],dip[20];
	unsigned short IP_header_length;
	
	/* For simplicity, we assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header))
		{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Ethernet header");
		return;
		}

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	/*extract the Source and destination IP from the ip header*/
	struct iphdr *iph = (struct iphdr *)packet;
	memset(&source, 0, sizeof(source));
    	source.sin_addr.s_addr = iph->saddr;
    	memset(&dest, 0, sizeof(dest));
    	dest.sin_addr.s_addr = iph->daddr;

	if (capture_len < sizeof(struct iphdr))
		{ /* Didn't capture a full IP header */
		too_short(ts, "IP header");
		return;
		}

	IP_header_length = iph->ihl * 4;	/* ip_hl is in 4-byte words */
	//printf("ip header length %d \n",IP_header_length);


	/* Skip over the IP header to get to the TCP header. */
	struct tcphdr *tcp = (struct tcphdr*)(packet + IP_header_length);
	
	//printf("source port %u \n",ntohs(tcp->source));
	packet += IP_header_length;
	capture_len -= IP_header_length;

	if (capture_len < sizeof(struct tcphdr))
		{
		too_short(ts, "TCP header");
		return;
		}

/*****using switch case....Case 1 is for TELNET packets, Case 2 is for FTP packets, Case 3 is for HTTP packets**********/
	switch(protocol[0])
	{
	case '1':
/*****************for TELNET Packets*********************************************/
//If the payload ends with the /r/n then the Seq no. of the next payload is dependent on the previous ACK packet rather than the
	if(test==0)			//if it is the end of the stream
	     {
	     if((ntohs(tcp->source)==23) || (ntohs(tcp->dest)==23))
		{
		//TCP_header_length = tcph->doff*4;
		c++;
		packet+=tcp->doff*4;
		capture_len-=tcp->doff*4;
		//printf("count : %d %s: ",c,inet_ntoa(source.sin_addr));
		//printf("Seq no: %d\n",ntohl(tcp->seq));
		//printf("Ack no: %d\n",ntohl(tcp->ack_seq));
		cur_seq=ntohl(tcp->seq);
		//printf("after the end of stream check %d = %d\n",cur_seq,prev_ack);
		if(cur_seq==prev_ack)
		{
		PrintTelnetData(packet , capture_len );
		}
		prev_ack=ntohl(tcp->ack_seq);
		}
		
		test=1;
		break;
	    }
	else if(test==1)
	    {
	    if((ntohs(tcp->source)==23) || (ntohs(tcp->dest)==23) && (unsigned int)tcp->psh==1 )
		{
		//TCP_header_length = tcph->doff*4;
		c++;
		packet+=tcp->doff*4;
		capture_len-=tcp->doff*4;
		//printf("count : %d %s: ",c,inet_ntoa(source.sin_addr));
		//printf("Seq no: %d\n",ntohl(tcp->seq));
		//printf("Ack no: %d\n",ntohl(tcp->ack_seq));
		cur_seq=ntohl(tcp->seq);
		
		if((packet[0]==13&&packet[1]==10) ||(packet[capture_len-2]==13&&packet[capture_len-1]==10))
			{
			test=0;
			//printf("checking %d %d %d %d",packet[0],packet[1],packet[capture_len-2],packet[capture_len-1]);
			}
		//printf("%d = %d\n",cur_seq,prev_ack);
		if(cur_seq==prev_ack)
		{
		PrintTelnetData(packet , capture_len );
		}
		prev_ack=ntohl(tcp->ack_seq);
		}
		break;
	    }
	case '2':
/*****************for FTP Packets*********************************************/

	if((ntohs(tcp->source)==21) || (ntohs(tcp->dest)==21) && (unsigned int)tcp->psh==1 )
		{
		//TCP_header_length = tcph->doff*4;
		//skip over the TCP encapsulation
		packet+=tcp->doff*4;
		capture_len-=tcp->doff*4;
		//printf("Source IP: %s    to   Destination IP: %s  \n",inet_ntoa(source.sin_addr),inet_ntoa(dest.sin_addr));
		//printf("%s: ",inet_ntoa(source.sin_addr));
		PrintData(packet , capture_len );
		}
		break;
	case '3':
/****************for HTTP Packets*************************************************/
	if(((ntohs(tcp->source)==80) || (ntohs(tcp->dest)==80)) )
		{
		
		//TCP_header_length = tcph->doff*4;
		//packet += sizeof(tcp);
		//capture_len -= sizeof(tcp);
		
		packet+=tcp->doff*4;
		capture_len-=tcp->doff*4;
		if (packet[k]==71 && packet[k+1]==69 && packet[k+2]==84 && count%2==1)
			{printf("*************HTTP %c%c%c Request************** \n",packet[k],packet[k+1],packet[k+2]);
			printf("Source IP: %s \n",inet_ntoa(source.sin_addr));
    			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));}
		if(packet[k]==72 && packet[k+1]==84 && packet[k+2]==84 && packet[k+3]==80 && packet[k+4]==47 && packet[k+5]==49 && packet[k+6]==46 && packet[k+7]==49 && count%2==1)
			{printf("*************HTTP Response************** \n");
			printf("Source IP: %s     ",inet_ntoa(source.sin_addr));
    			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));}
		count++;
		strcpy(sip,inet_ntoa(source.sin_addr));
		strcpy(dip,inet_ntoa(dest.sin_addr));
		//printf("sip:%s",sip);
		//printf("dip:%s",dip);
		count++;
		PrintData(packet, capture_len);
		//reassemble(packet, capture_len,sip,dip);
		break;
		}
	
	}
}	


int main(int argc, char *argv[])
	{
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 2 )
		{
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
		}

	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL)
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}

	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	
	while ((packet = pcap_next(pcap, &header)) != NULL)
		dump_TCP_packet(packet, header.ts, header.caplen, argv[1]);

	// terminate
	return 0;
	}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
	{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
	}

void problem_pkt(struct timeval ts, const char *reason)
	{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
	}

void too_short(struct timeval ts, const char *truncated_hdr)
	{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
	}



void PrintData (const unsigned char* data , int Size)
{
    
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%80==0)   //if one line of hex printing is complete...
        {
            
            for(j=i-80 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else continue; //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%80==0) 
            //printf(" %c",(unsigned char)data[i]);
            continue;     
        if( i==Size-1)  //print the last spaces
        {
            
             
            for(j=i-i%80 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else continue;
            }
            printf("\n");
        }
    }
}

int i,j,k=0,counter=0,l=0,len_of_data=0,mov_pos=0,limiter;
char buf[5000],buf3[10000]="\0";
char temp[6000],temp2[10000];
char *buf1,*buf2;
int *len;

void PrintTelnetData (const unsigned char* data , int Size)
{
    //printf("first element : %d \n",(int)data[0]);
    //printf("size of payload %d \n",Size);
    for(i=0 ; i < Size ; i++)
    {
        if(data[i]>=32 && data[i]<=128)
		{printf("%c",(unsigned char)data[i]);
		//if(i==79 || i==Size-1 )
		if(i==79)
			printf("\n");
          	}
	else if(data[i]==13)
		printf("\n");
	     else
		continue;
    }
}

void reassemble(const unsigned char* data , int Size,char *sip,char *dip)
{

count++;
int i=count-1;
struct array *a;
a=(struct array*)malloc(sizeof(struct array));
	char *buf2 = (char *)malloc(sizeof(char)*200*100);//store ip
	char *buf1 = (char *)malloc(sizeof(char)*50000*900);//store data
	int *len = (int *)malloc(sizeof(int)*100);
if(count==1)
	{

	strcpy(buf2,"\0");
	strcpy(buf1,"\0");}//net size}
/*
if(count>=1)
	{a=(struct array*)realloc(a,sizeof(struct array)*count);
	buf2 = (char *)realloc(buf2,sizeof(char)*200*count);//store ip
	buf1 = (char *)realloc(buf1,sizeof(char)*50000*count);//store data
	len = (int *)realloc(len,sizeof(int)*count);}//net size}*/
k=0;
strcpy(a[i].x,sip);
strcpy(a[i].y,dip);
	//scanf("%d%d",&a[i].x,&a[i].y);
printf("\n s ip %s d ip %s",a[i].x,a[i].y);
strcpy(temp,data);
len_of_data+=strlen(temp);
k=0;
l=0;
counter=0;
for (j=0;j<i;j++)
{
l+=*(len+j);
	
	if (((a[i].x)==a[j].x)&&((a[i].y)==a[j].y))
	{	
		k=1;
		counter++;
		if (counter !=0)
		{
			*(len+i) = strlen(temp);
			*(len+j) = *(len+i)+*(len+j);
			limiter = abs(len_of_data - 2*l);
			for (k=l,mov_pos=0;mov_pos<=limiter;k++,mov_pos++)		
			{
				temp2[k-l]=*(buf1+k);
			}
			printf("\nl is %d length of data is %d\n",l,len_of_data);
			memcpy(buf3,buf1,l);
			printf("buf3 is %s buf1 is %s\n",buf3,buf1);
			printf("\n5\n");
			strcat(buf3,temp);
			printf("buf3 after temp %sand temp2%s\n",buf3,temp2);
			strcat(buf3,temp2);
			printf("buf3 after temp2 %s\n",buf3);
			printf("\n6\n");
			strcpy(buf1,buf3);
			printf(" final buf1 is %s\n",buf1);
		}						
	}
	bzero(buf3,100);
}
	printf("%d %d %d %d chech \n",k,i,j,i-counter+1);
	if (k==0)		//-1 because we are increasein 1 in first iteration
	{
		strcat(buf1,temp);
		*(len+i-counter)=strlen(temp);
		strcpy(temp,a[i].x);
		strcat(buf2,temp);
		strcpy(temp,a[i].y);
		strcat(buf2,temp);
	}



//for(i=0;i<6;i++)
//	printf("len = %d \n",*(len+i));
if(count>10)
	printf("data:%s  \n",buf1);
}


