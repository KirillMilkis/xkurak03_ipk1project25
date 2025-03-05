CXX = g++

CXXFLAGS = -std=c++17 -Wall -Wextra  -I/opt/homebrew/Cellar/libnet/1.3/include

SRC_DIR = src

SOURCES = $(wildcard $(SRC_DIR)/*.cpp)

TARGET = ipk-l2l3-scan

LDFLAGS = -L/opt/homebrew/Cellar/libnet/1.3/lib -lnet -lpcap 

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)


