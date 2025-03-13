#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("Packet captured with length: %d\n", pkthdr->len);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	handle = pcap_open_live("wlan0" , BUFSIZ , 1 , 1000 , errbuf);
	if(handle == NULL){
		fprintf(stderr , "Couldnt Open Device: %s\n" , errbuf);
		return 1;
	}
	pcap_loop(handle , 0 , packet_handler , NULL);
	pcap_close(handle);
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
