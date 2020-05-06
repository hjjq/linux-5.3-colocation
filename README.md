# Linux kernel with co-location vulnerability aware pblk
Able to detect duplicate data blocks written to pblk that are mapped to the same LUN (co-location vulnerability)
Eliminates co-location vulnerability by changing pblk's L2P mapping scheme.
ToDo: 
1. Changes may cause some benchmarks to crash, for a more robust solution need to change other components of pblk (e.g. garbage collection, recovery).
2. Linux hashmap used in pblk-map.c will grow indefinitely. Need to implement garbage collection for kernel DRAM.

## Setup
QEMU is required to emulate an OCSSD. Detailed steps can be found at https://github.com/OpenChannelSSD/qemu-nvme

## Building and installing the kernel
```
make
sudo make install
```
## Mounting btrfs on the OCSSD
```
sudo modprobe pblk
sudo nvme lnvm create -d nvme0n1 --lun-begin=0 --lun-end=127 -n myocssd -t pblk -f
sudo mkfs.btrfs -m dup /dev/myocssd
sudo mount /dev/myocssd /mnt
```
For btrfs, the -m dup option will force metadata duplication. To turn off, use -m single

