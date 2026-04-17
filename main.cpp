#include <iostream>
#include <pcap.h>
#include <cstring>

using namespace std;

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    int radiotap_len = packet[2];
    
    const u_char* wifi = packet + radiotap_len;
    
    uint16_t frame_control = wifi[0] | (wifi[1] << 8);
    uint8_t type = (frame_control >> 2) & 0x3;
    uint8_t subtype = (frame_control >> 4) & 0xF;
    
    if (type == 0 && subtype == 8) {
        const u_char* bssid = wifi + 16;
        
        const u_char* data = wifi + 24;
        int data_len = header->caplen - radiotap_len - 24;
        
        for (int i = 0; i < data_len - 1; i++) {
            if (data[i] == 0x00) {
                int ssid_len = data[i + 1];
                if (ssid_len > 0 && ssid_len <= 32 && i + 2 + ssid_len <= data_len) {
                    char ssid[33];
                    memcpy(ssid, data + i + 2, ssid_len);
                    ssid[ssid_len] = '\0';
                    
                    char bssid_str[18];
                    snprintf(bssid_str, sizeof(bssid_str), 
                             "%02x:%02x:%02x:%02x:%02x:%02x",
                             bssid[0], bssid[1], bssid[2],
                             bssid[3], bssid[4], bssid[5]);
                    
                    cout << "Wi-Fi: " << ssid << " | MAC: " << bssid_str << endl;
                    break;
                }
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_open_live("mon0", 65536, 1, 1000, errbuf);
    
    if (!handle) {
        return 1;
    }
    
    cout << "Wi-Fi webs" << endl;
    
    pcap_loop(handle, -1, packet_handler, nullptr);
    
    pcap_close(handle);
    return 0;
}

// sudo iw phy phy0 interface add mon0 type monitor
// sudo ip link set mon0 up
// sudo iw dev mon0 del
