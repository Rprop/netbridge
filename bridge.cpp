#define _HAS_EXCEPTIONS 0
#include <thread>
#include "npcap.h"
#include <tchar.h>
#define DOT_IP(s)      ((unsigned char *)s)[0], ((unsigned char *)s)[1], ((unsigned char *)s)[2], ((unsigned char *)s)[3]
#define DOT_MAC(s)     ((unsigned char *)s)[0], ((unsigned char *)s)[1], ((unsigned char *)s)[2], ((unsigned char *)s)[3], ((unsigned char *)s)[4], ((unsigned char *)s)[5]
#define DOT_IPF        "%u.%u.%u.%u"
#define DOT_MACF       "%.2x.%.2x.%.2x.%.2x.%.2x.%.2x"

//-------------------------------------------------------------------------

#define ETHER_DEV      "\\Device\\NPF_{75182FD2-8975-4BE6-9DED-E54F510F63DD}"
#define VIRTUAL_DEV    "\\Device\\NPF_{5354E123-71F3-4ED0-BE97-6A9BFFFADA4D}"
#define SELF_MAC       "88:fa:e3:3d:62:88"

//-------------------------------------------------------------------------

int main()
{
#ifdef _DEBUG
	npcap::findalldevs();
#endif // _DEBUG
	
	// https://github.com/nmap/npcap/releases/tag/v0.05-r6
	HKEY hNpcap;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\npcap"), NULL, KEY_SET_VALUE, &hNpcap) == ERROR_SUCCESS) {
		RegSetKeyValue(hNpcap, NULL, _T("SendToRxAdapters"), REG_SZ, _T(VIRTUAL_DEV), sizeof(_T(VIRTUAL_DEV)));
		RegCloseKey(hNpcap);
		// TODO: restart npcap
	} else {
		fprintf(stderr, "Error in enabling send-to-Rx adapter\n");
	} //if

	// traffic from VIRTUAL_DEV/SELF_MAC will be forwarded to ETHER_DEV and vice versa
	pcap_t *fp = npcap::opendev(ETHER_DEV, PCAP_D_IN);
	if (fp != NULL) {
		bpf_program filter[2];
//		npcap::setfilter(fp, "not (ether host d8:50:e6:e2:2c:f6 or 01:80:c2:00:00:00 or ether src " SELF_MAC ")", &filter[0]);
		npcap::setfilter(fp, "ether dst " SELF_MAC " or (ether dst ff:ff:ff:ff:ff:ff and not ether src " SELF_MAC ")", &filter[0]);
		pcap_t *sp = npcap::opendev(VIRTUAL_DEV, PCAP_D_OUT);
		if (sp != NULL) {
//			npcap::setfilter(sp, "not ether dst " SELF_MAC, &filter[1]);
			npcap::setfilter(sp, "ether src " SELF_MAC, &filter[1]);
			std::thread([](pcap_t *fp, pcap_t *sp) {
				pcap_pkthdr *header;
				const u_char *pkt_data;
				int ret;
				while ((ret = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
// 					if (header->caplen > sizeof(ether_hdr)) {
// 						auto eth = reinterpret_cast<const ether_hdr *>(pkt_data);
// 						printf("income %u, " DOT_MACF "->" DOT_MACF "\n", header->caplen, DOT_MAC(eth->ether_shost), DOT_MAC(eth->ether_dhost));
// 					} //if
					if (ret > 0) pcap_sendpacket(sp, pkt_data, header->caplen);
				}
			}, fp, sp);
			pcap_pkthdr *header;
			const u_char *pkt_data;
			int ret;
			while ((ret = pcap_next_ex(sp, &header, &pkt_data)) >= 0) {
// 				if (header->caplen > sizeof(ether_hdr)) {
// 					auto eth = reinterpret_cast<const ether_hdr *>(pkt_data);
// 					if (memcmp(eth->ether_shost, SELF_MAC, ETHER_ADDR_LEN - 2) == 0) {
// 					} //if
// 					printf("outcome %u, " DOT_MACF "->" DOT_MACF "\n", header->caplen, DOT_MAC(eth->ether_shost), DOT_MAC(eth->ether_dhost));
// 				} //if
				if (ret > 0) pcap_sendpacket(fp, pkt_data, header->caplen);
			}
			npcap::freefilter(&filter[1]);
			npcap::close(sp);
		} //if
		npcap::freefilter(&filter[0]);
		npcap::close(fp);
	} //if

	return 0;
}

