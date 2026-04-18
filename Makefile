CXX := g++
CXXFLAGS := -std=c++23 -O2 -Wall -Wextra -pedantic
LDFLAGS := -lcrypto
TARGET := guardfs
SRC := guardfs.cpp

.PHONY: all clean run once

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

once: $(TARGET)
	./$(TARGET) --once

clean:
	rm -f $(TARGET)
