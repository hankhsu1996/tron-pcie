import os
import multiprocessing as mp

from typing import List

AXI_MODE_AXI_LITE = 0
AXI_MODE_AXI_FULL = 1

BURST_MODE_FIXED = 0
BURST_MODE_INCRMENTAL = 1

FUNCTION_READ = 0
FUNCTION_WRITE = 1
FUNCTION_WAIT = 2


class PacketError(Exception):
    def __init__(self, message="Packet returns error status."):
        self.message = message
        super().__init__(self.message)


class ChecksumError(Exception):
    def __init__(self, message="Checksum failed."):
        self.message = message
        super().__init__(self.message)


class PCIeDriver:
    def __init__(self, device):
        self.device = device
        self.fpga = -1

        self.fpga_fd = os.open(self.device, os.O_RDWR)

    def write(self, block: bytearray) -> None:
        os.write(self.fpga_fd, block)

    def read(self, size: int = 1024) -> bytes:
        return os.read(self.fpga_fd, size)

    def __del__(self):
        os.close(self.fpga_fd)


class PCIe:

    def __init__(self, h2c_device: str = '/dev/xdma0_h2c_0', c2h_device: str = '/dev/xdma0_c2h_0'):
        self.h2c_driver = PCIeDriver(device=h2c_device)
        self.c2h_driver = PCIeDriver(device=c2h_device)

    def printBlock(self, block: bytes):
        assert len(block) % 4 == 0

        print()
        for i in range(0, len(block), 4):
            w = int.from_bytes(block[i:i+4], byteorder='little')
            print(f"{i:4d}: {w:08x}")

    def printBlockBytes(self, block: bytes):
        print(block)

    def genChecksum(self, block: bytearray):
        assert len(block) % 4 == 0
        mask = 0xffffffff

        accumulate = 0
        for i in range(0, len(block), 4):
            w = int.from_bytes(block[i:i+4], byteorder='little')
            accumulate += w

        while accumulate >> 32:
            accumulate = (accumulate & mask) + (accumulate >> 32)

        checksum = ~accumulate & mask
        assert(accumulate + checksum == mask)
        return checksum.to_bytes(4, byteorder='little')

    def send_packet(self, task_id: int, status: int, axi_mode: int, burst_mode: int,
                    function: int, src_dev_num: int, dest_dev_num: int,
                    address: int, bytes_num: int, verbose: bool = False):

        assert(0 <= task_id < 2**16)
        assert(0 <= status < 2**6)
        assert(0 <= axi_mode < 2**2)
        assert(0 <= burst_mode < 2**2)
        assert(0 <= function < 2**6)
        assert(0 <= src_dev_num < 2**16)
        assert(0 <= dest_dev_num < 2**16)
        assert(0 <= bytes_num < 2 ** 16 and bytes_num % 4 == 0)

        header1_str = f'{task_id:016b}{status:06b}{axi_mode:02b}{burst_mode:02b}{function:06b}'
        header1 = int(header1_str, 2).to_bytes(4, byteorder='little')

        header2_str = f'{src_dev_num:016b}{dest_dev_num:016b}'
        header2 = int(header2_str, 2).to_bytes(4, byteorder='little')

        header3 = address.to_bytes(4, byteorder='little')

        header4 = bytes_num.to_bytes(4, byteorder='little')

        block = b''.join([
            header1,
            header2,
            header3,
            header4
        ])

        block += self.genChecksum(block)

        self.h2c_driver.write(block)

    def receivePacket(self, size: int = 1024, verbose: bool = False):
        parsed = self.parse_packet(self.c2h_driver.read(size=size))

        print(parsed)

    def checkSum(self, block: bytes) -> bool:
        assert(len(block)) % 4 == 0

        mask = 0xffffffff
        accu = 0

        for i in range(0, len(block), 4):
            accu += int.from_bytes(block[i:i+4], byteorder='little')
        return accu == mask

    def parse_packet(self, packet: bytes) -> dict:
        assert(len(packet) % 4 == 0)

        if not self.checkSum(packet):
            raise ChecksumError

        parsed = dict()

        packet_li = [int.from_bytes(packet[i:i+4], byteorder='little')
                     for i in range(0, len(packet), 4)]

        # Header 1
        header1 = packet_li[0]
        parsed['task_id'] = (header1 & 0xffff0000) >> 16
        parsed['status'] = (header1 & 0x0000fc00) >> 10

        # handle exception
        if parsed['status'] == 2:
            raise PacketError("Act fail")
        elif parsed['status'] == 3:
            raise PacketError("Address fail")
        elif parsed['status'] == 4:
            raise PacketError("Checksum fail")
        elif parsed['status'] == 5:
            raise PacketError("Command frame fail")
        elif parsed['status'] == 6:
            raise PacketError("Command bytes fail")
        elif parsed['status'] == 7:
            raise PacketError("Command length fail")
        elif parsed['status'] == 8:
            raise PacketError("Timeout fail")
        elif parsed['status'] == 9:
            raise PacketError("Destination device number fail")

        parsed["axi_mode"] = (header1 & 0x00000300) >> 8
        parsed["burst_mode"] = (header1 & 0x000000c0) >> 6
        parsed["function"] = (header1 & 0x0000003f) >> 0

        # Header 2
        header2 = packet_li[1]
        parsed["src_dev_num"] = (header2 & 0xffff0000) >> 16
        parsed["dest_dev_num"] = (header2 & 0x0000ffff) >> 0

        # Wait Response does not have header 3, parse it first
        if parsed["function"] == FUNCTION_WAIT:
            return parsed
        else:
            header3 = packet_li[2]
            parsed["address"] = (header3 & 0xffffffff) >> 0
            header4 = packet_li[3]
            parsed["bytes_num"] = (header4 & 0xffffffff) >> 0

            if parsed["function"] == FUNCTION_READ:
                parsed["payload"] = packet[4*4:-1*4]
                return parsed
            elif parsed["function"] == FUNCTION_WRITE:
                return parsed
            else:
                raise ValueError("No such function")


if __name__ == '__main__':
    h2c_device = '/dev/xdma0_h2c_0'
    c2h_device = '/dev/xdma0_c2h_0'

    pcie = PCIe(h2c_device=h2c_device, c2h_device=c2h_device)

    task_id = 112
    status = 0
    axi_mode = 0
    burst_mode = 0
    function = 0
    src_dev_num = 0
    dest_dev_num = 0xc8b5
    address = 0xc0000000
    bytes_num = 500
    verbose = True

    wr_args = (task_id, status, axi_mode, burst_mode, function,
               src_dev_num, dest_dev_num, address, bytes_num, verbose)

    size = 1024
    rd_args = (size, verbose)

    rd = mp.Process(target=pcie.receivePacket, args=rd_args)
    wr = mp.Process(target=pcie.send_packet, args=wr_args)

    rd.start()
    wr.start()

    rd.join()
    wr.join()
