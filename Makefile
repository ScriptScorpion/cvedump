CC := g++
CCF := -std=c++17 -O1
SOURCE := main.cpp
TARGET := cvedump
main:
	@if [ "$$(id -u)" -ne 0 ]; then \
        echo "Please run make with root privileges"; \
        exit 1; \
    fi
	@$(CC) $(CCF) $(SOURCE) -o $(TARGET)
	@mv $(TARGET) /usr/local/bin

