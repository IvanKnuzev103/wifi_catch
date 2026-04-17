#include <iostream>
#include <zmq.hpp>
#include <nlohmann/json.hpp>

int main() {
    zmq::context_t ctx(1);
    zmq::socket_t sub(ctx, zmq::socket_type::sub);
    sub.connect("tcp://localhost:5556");
    sub.set(zmq::sockopt::subscribe, "");
    
    std::cout << "Listening for Wi-Fi networks..." << std::endl;
    
    while (true) {
        zmq::message_t msg;
        auto result = sub.recv(msg, zmq::recv_flags::none);
        
        if (!result) continue;
        
        std::string json_str(static_cast<char*>(msg.data()), msg.size());
        
        try {
            auto j = nlohmann::json::parse(json_str);
            std::cout << "Wi-Fi: " << j["ssid"] << " | MAC: " << j["bssid"] << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    
    return 0;
}