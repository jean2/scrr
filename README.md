Self-Clocked Round Robin Packet Scheduling Paper Artifacts
==============================================

Please check out our paper at https://www.usenix.org/conference/nsdi25/presentation/sharafzadeh.
Citation key:
```
@INPROCEEDINGS{scrr,
  title={Self-Clocked Round-Robin Packet Scheduling},
  author={Sharafzadeh, Erfan and Matson, Raymond and Tourrilhes, Jean and Sharma, Puneet and Ghorbani, Soudeh},
    booktitle   = "NSDI",
    year        = "2025"
}
```

SCRR is a low-latency, zero-configuration, and fair packet scheduling paradigm that aims to replace existing fair packet schedulers such as Deficit Round-Robin (DRR).

This repository contains the qdisc implementation of SCRR and all the packets schedulers we tested in our paper, as well as tc modules and Linux kernel patches to replicate our test environment. Check the paper for explanation of the provided schduling modules.

## Setting Up The Environment

### Preparing the Kernel
1. Download and decompress Linux kernel 6.1
2. Apply the provided patches (`*.diff`). The patches include l4s functionality and support for TCP BBRv3.
3. Copy the qdisc modules (`sch_*.c` into kernel's `net/sched/`)
4. Add the sources to the corresponding Makefile in `net/sched/Makefile`:
```
obj-$(CONFIG_NET_SCH_SCRR)   += sch_scrr.o
``` 
5. Add the qdiscs to kernel's KConfig in `net/sched/Kconfig`:
```
 config NET_SCH_SCRR
      tristate "self-clocked round-robin packet scheduler"
      help
        Say Y here if you want to use the SCRR Scheduler.
        To compile this code as a module, choose M here: the module
        will be called sch_scrr.
 
        If unsure, say N.
 ```
 Make sure to follow steps 4 and 5 for each qdisc module separately.
6. Compile and install the kernel:
```
make -j
make modules_install
sudo make install
reboot
```

7. If modules are not loaded, or you used `make modules` to only build kernel modules, use `modprobe sch_scrr`, or `insmod sch_scrr.ko` where appropriate to load the module.

### Preparing iproute2
1. Download iproute2 sources for kernel 6.1
2. Unpack the archive and copy the tc modules (`q_*.c`) into `tc/` directory.
3. Add the entries in `tc/Makefile`:
```
TCMODULES += q_scrr.o
```
4. Build iproute and install the excecutable in your path.

### Loading the Scheduler
To load SCRR, use your custom built tc. 
```
tc qdisc add dev NETDEVICE root scrr
```

## Experiment Data
We have published the raw experiment data of SCRR paper at https://zenodo.org/records/14963380.

The data is in gzip format. After decompressing the archives, the following files are accessible:
```
*snd.icsv   -> iperf sender log
*rcv.icsv   -> iperf receiver log
*tcstats.txt    -> tc -s output
*.kperf     -> perf output (used to measure CPU utilization of modules)
*.pcap      -> packet capture data for some experiments
```

Method names can be decoded from file names. Files usually follow this format `SENDER-IP_RECEIVER-IP_METHOD-ID_*`
Methods used in the paper correspond to the following IDs:
```
74  -> 'aifo'
83  -> 'drr+sfo-500'
84  -> 'drr+sfo-200'
86  -> 'drr+sfo_1500'
87  -> 'drr+sfo_9000'
92  -> 'scrr'
98  -> 'scrr-nmne'
99  -> 'scrr-npm'
101 -> 'stfq'
102 -> 'sp-pifo'
111 -> 'scrr-neia'
113 -> 'drr-200'
114 -> 'drr-500'
116 -> 'drr-1500'
117 -> 'drr-9000'
120 -> 'scrr-basic'

```

Please contact the authors for additional information about using the artifacts.

----
SCRR Authors
March 2025
