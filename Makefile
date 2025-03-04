CXX = g++

CXXFLAGS = -std=c++17 -Wall -Wextra

SRC_DIR = src

SOURCES = $(wildcard $(SRC_DIR)/*.cpp)

TARGET = ipk-l2l3-scan

LDFLAGS = -lpcap

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)


