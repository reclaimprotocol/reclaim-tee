CC = gcc
GO = go
CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared

TARGET = libreclaim.so
HEADER = libreclaim.h
SOURCE = libreclaim.go

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(GO) build -buildmode=c-shared -o $(TARGET) $(SOURCE)

install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	cp $(HEADER) /usr/local/include/
	ldconfig

test: $(TARGET)
	@echo "Testing shared library..."
	@echo "Library built successfully: $(TARGET)"

clean:
	rm -f $(TARGET) *.h

# Development targets
dev: clean all test

# Show library info
info: $(TARGET)
	@echo "Library information:"
	@file $(TARGET)
	@echo ""
	@echo "Symbols:"
	@nm -D $(TARGET) | grep reclaim_ || echo "No reclaim_ symbols found" 