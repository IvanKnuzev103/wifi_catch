CXX = g++
CXXFLAGS = -std=c++17 -Wall

all: sniffer viewer

sniffer: sniffer.cpp
	$(CXX) $(CXXFLAGS) sniffer.cpp -o sniffer -lpcap -lzmq

viewer: viewer.cpp
	$(CXX) $(CXXFLAGS) viewer.cpp -o viewer -lzmq

clean:
	rm -f sniffer viewer

run-sniffer: sniffer
	sudo ./sniffer

run-viewer: viewer
	./viewer