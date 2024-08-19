.SILENT:

NVCC = nvcc
CFLAGS = -rdc=true
TARGET = cracker
SRCS = cracker.cu md5.cu

all: $(TARGET)

$(TARGET): $(OBJS)
	$(NVCC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
