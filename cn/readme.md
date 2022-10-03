## Introduction

*Compute Node DP notification* submodule allows CN(Compute Node) to recognize extra Arion-DP OAM information in incoming packets from
Arion DP, parsing them and sending them over to *OAM receiver*, a RESTful service in ACA(Alcore Control Agent). *OAM receiver* can
then update OVS rules to allow direct CN to CN communication instead of going through Arion DP. *CN DP notification* submodule is
optional, Arion-DP gateway works with/without this submodule, the difference is without *CN DP notification* submodule, the extra OAM 
information in incoming packets are silently ignored.

The *CN DP notification* works with Arion DP framework and tested on Ubuntu. With CN runing on Ubuntu 18.04+ and Arion DP on Ubuntu 22.04.

## Prerequisites

*CN DP notification* is a submodule that is built and deployed only in Compute Node when needed. For this submodule to be effective:
  - the Arion DP cluster needs to be deployed with *DP notification* turned on;
  - on Compute Node side, ACA needs to be started with OAM receiver RestFul service enabled.

Please note Arion DP gateway works for CNs with or without ACA and/or this submodule deployed on CN side.

## Build and Deploy

1. Currently this submodule works on Linux kernel 5.6+, the follow scripts will check CN kernel version and update them if needed:

       $ cd ./cn
       $ ./bootstraps.sh

2. Once the above step is completed, build the submodule:

       $ cd cn_dpnd
       $ make

3. Once step 2 is completed, loading this submodule is easy:

       $ sudo ./cn_dpnd_usr -d [interface] --force


    You can run with -h to see various options:
  
       $ sudo ./cn_dpnd_user -h
  

# Test

  This submodule is tested and verified in bare-metal lab environment.