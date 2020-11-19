# PCIe Python Application

## Introduction

This is the Python application of DMA/Bridge subsystem for PCI Express. Currently, there are two Python files:

- `app.py`: It can send, receive, parse packet. The sending and receiving processes is non-blocking.
- `reg_rw.py`: It can read `/dev/xdma0_control` register value.

Before running the files, make sure the [XDMA driver](https://github.com/Xilinx/dma_ip_drivers/tree/master/XDMA/linux-kernel) is correctly installed.
