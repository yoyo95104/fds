#include <iostream>
#include <pcap/pcap.h>
#include <string>
#include <vector>
#define threshold 1000

int packetCount = 0;
std::vector<std::string> signatures = {
    "malicious_pattern_1",
    "malicious_pattern_2",
    "malicious_pattern_3"
};

void analyzePacket(const std::string& packet) {
    for (const auto& signature : signatures) {
        if (packet.find(signature) != std::string::npos) {
            std::cout << "ALERT: Malicious packet detected (Signature: " << signature << ")!\n";
            return;
        }
    }
    std::cout << "Packet is safe.\n";
}
void analyzelen(const std::string& pcaket) {
	packetCount++;
    	if (packetCount > threshold) {
        	std::cout << "ALERT: High traffic detected (Packet count: " << packetCount << ")!\n";
    	}
}
void runAnalysis(const std::string& packet) {
    while(1){
    	std::cout << "Running analysis on packet: " << packet << "\n";
    	analyzePacket(packet);
	analyzelen(packet);
    }
}
