import mmap


class RegRW:
    def __init__(self, control_device='/dev/xdma0_control', mem_device='/dev/mem'):
        self.control_device = control_device
        self.mem_device = mem_device

    def readReg(self, address):
        with open(self.control_device, 'rb') as f:
            mm = mmap.mmap(f.fileno(), mmap.PAGESIZE *
                           16, mmap.MAP_SHARED, mmap.PROT_READ)
            mm.seek(address)
            reg = int.from_bytes(mm.read(4), 'little')
            return reg

    def getC2HDescriptorAddr(self):
        lowAddr = self.readReg(0x5080)
        highAddr = self.readReg(0x5084)
        address = (highAddr << 32) + lowAddr
        return address

    def getC2HDescriptorField(self, offset):
        desc_base_addr = self.getC2HDescriptorAddr() + offset
        desc_base_addr = desc_base_addr & ~(mmap.PAGESIZE - 1)
        print(f'The descriptor base address is 0x{desc_base_addr:016x}')
        # Not yet finished. Currently, it can only retrieve the base address of the descriptor


rw = RegRW()
rw.getC2HDescriptorField(0x0)
