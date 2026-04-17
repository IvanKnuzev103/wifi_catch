#include <iostream>
#include <pcap.h>
#include <zmq.hpp>
#include <nlohmann/json.hpp>
#include <cstring>

using namespace std;

int main() {
    zmq::context_t ctx(1);
    zmq::socket_t pub(ctx, zmq::socket_type::pub);
    pub.bind("tcp://*:5556");
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("mon0", 65536, 1, 1000, errbuf);
    
    if (!handle) {
        cerr << "Error: " << errbuf << endl;
        cerr << "Create mon0: sudo iw phy phy0 interface add mon0 type monitor" << endl;
        return 1;
    }
    
    cout << "Sniffer started. Sending to tcp://*:5556" << endl;
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        if (pcap_next_ex(handle, &header, &packet) == 1) {
            int radiotap_len = packet[2];
            const u_char* wifi = packet + radiotap_len;
            
            uint16_t frame_control = wifi[0] | (wifi[1] << 8);
            uint8_t type = (frame_control >> 2) & 0x3;
            uint8_t subtype = (frame_control >> 4) & 0xF;
            
            if (type == 0 && subtype == 8) {
                const u_char* bssid = wifi + 16;
                
                char bssid_str[18];
                snprintf(bssid_str, sizeof(bssid_str), 
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         bssid[0], bssid[1], bssid[2],
                         bssid[3], bssid[4], bssid[5]);
                
                const u_char* data = wifi + 24;
                int data_len = header->caplen - radiotap_len - 24;
                
                string ssid = "";
                for (int i = 0; i < data_len - 1; i++) {
                    if (data[i] == 0x00) {
                        int ssid_len = data[i + 1];
                        if (ssid_len > 0 && ssid_len <= 32 && i + 2 + ssid_len <= data_len) {
                            ssid = string((char*)(data + i + 2), ssid_len);
                            break;
                        }
                    }
                }
                
                nlohmann::json j;
                j["ssid"] = ssid.empty() ? "[Hidden]" : ssid;
                j["bssid"] = bssid_str;
                j["rssi"] = -50;
                
                string msg = j.dump();
                zmq::message_t zmq_msg(msg.size());
                memcpy(zmq_msg.data(), msg.c_str(), msg.size());
                pub.send(zmq_msg, zmq::send_flags::none);
                
                cout << "Sent: " << msg << endl;
            }
        }
    }
    
    pcap_close(handle);
    return 0;
}