CC := g++
CCF := -std=c++17 -O1
SOURCE := main.cpp
TARGET := cvedump
main:
	@if [ "$$(id -u)" -ne 0 ]; then \
        echo "Please run make with root privileges"; \
        exit 1; \
    fi
	@mkdir -p /opt/cvedump
	@wget -q -O /opt/cvedump/main.zip https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip
	@unzip -qq /opt/cvedump/main.zip
	@rm -f /opt/cvedump/main.zip 
	@mv /opt/cvedump/cvelistV5-main/* /opt/cvedump/ 
	@rm -rf /opt/cvedump/cvelistV5-main
	@$(CC) $(CCF) $(SOURCE) -o $(TARGET)
	@mv $(TARGET) /usr/local/bin

