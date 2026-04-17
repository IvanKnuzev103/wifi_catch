CXX = g++
CXXFLAGS = -std=c++17 -Wall
LIBS = -lzmq -lspdlog -lpcap -lfmt

TARGET = test

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) main.cpp $(LIBS) -o $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)