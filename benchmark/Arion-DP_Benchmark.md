# Arion DP Benchmark
09/15/2022

v0.3
## Introduction

This is an benchmark report for Arion DP network performance. We conducted the Throughput and Latency Benchmarking on single Wing as well as Arion DP cluster. 

We used different tools to conduct various benchmark tests. The results shown below are collected with netperf tests, although we also used iperf3 for comparision. The throughput benchmark uses netperf's TCP_STREAM test. TCP_RR and TCP_CRR are used to observe network latency.

Besides netperf benchmarking tests, we also conducted Redis benchmarking on Arion DP cluster.

The main comparision in benchmarking is between direct compute node communication vs communication via Arion Cluster between compute nodes, as well as via legacy zeta cluster between compute nodes.

## Test environment

The Ariond DP cluster is set up with: 
 - 6 bare-metal machines as Arion Wings
 - 10 bare-matal machines as Compute Nodes
	
Each Arion Wing in Arion cluster runs with Ubuntu 22.04. Compute Nodes run with Ubuntu 18.04.

  - CPU
    * Intel(R) Xeon(R) CPU E5-2640  0 @ 2.50GHz 12 cores/24 threads  (Wing)
    * Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz 16 cores/32 threads(Compute Node)
  - Network Card: Intel 82599ES 10-Gigabit SFI/SFP+ 
  - Kernel 
    * Linux 5.15(Ubuntu 22.04 LTS) (Wing)
    * Linux 4.15(Ubuntu 18.04 LTS) (Compute Node)

Zeta cluster is setup with Ubuntu 18.04 with Linux kernel updated to 5.6 under the same hardware type.

These machines are connected via 10G switches.

## Test setup

The tests shown here includes:
  - Direct(Node <-> Node): In this setup, no Arion Cluster is envolved. The benchmark is performed by directly running *netperf*  between docker containers in different bare metal machines with differnt MTUs:
    * MTU 1500
    * MTU 9000

  - Via Arion Cluster(Node <-> Wing <-> Node): In this setup, all traffic goes through a single Arion Wing, no direct path is allowed. Same *netperf* tests are conducted for following setup:
    * MTU 1500, generic mode
    * MTU 1500, generic mode, offband oam notification on
    * MTU 1500, driver mode
    * MTU 9000, generic mode

  - Legacy zeta cluster(Node <-> Zeta <-> Node): In this setup, single flow traffic goes through a specific Zeta GW node, no direct path is allowed. Same *netperf* tests are conducted for the following setup:
    * MTU 1500, generic mode
    * MTU 9000, generic mode (*can't* set up)

  - Arion DP cluster benchmarking with following setup
    - 6 subnet/30 containers on each CN, total 10 CNs
    - total 150 iperf tests between containers on different CNs launched at about the same time and run for 10mins

  - Redis benchmarking are conducted as following with default MTU 1500 and generic mode
    - Via Arion Cluster(Node <-> Wing <-> Node):
      - default redis-benchmarking
      - redis-benchmarking with larger packet size(1400 bytes)
    - Direct(Node <-> Node):
      - default redis-benchmarking
      - redis-benchmarking with larger packet size(1400 bytes)

## Summary of the Results

The tests are done with in house (*humble*) 10G network environment. Although Arion DP is a work in progress with more optimization and more features to be added on, we feel the initial finding in benchmarking is meaningful and could serve as a baseline for further development. Below are some observations about current Arion DP: 
 - communication via Arion Wing can reach about the same throughput as direct communication between compute nodes with neighbour rules(*close to line rate*);
 - Network delay to go through Arion Wing(CN-Arion-CN) in netperf TCP_RR test compared with direct CN-CN path can be as low as *21us*(XDP driver mode);
 - enabling XDP Driver mode has about *7%* performance improvement(both throughput and latency);
 - enabling offband Direct Path OAM capability in Arion DP has about *15%* performance downgrade in terms of throughput;
 - Arion DP can reach about *9.6Gbps* in 10G environment, legacy zeta cluster can only reach about 3.0Gbps, this is 3X difference. We can break down the causes as following:
    * XDP/eBPF is an active evolving technology, while legacy zeta uses libbpf v0.3(01/03/2021), Arion DP uses libbpf v0.8 (5/16/2022). Optimizations, bug fixes and new capabilities are added in recent year;
    * legacy Zata reaches about 3.0Gbps in our benchmarking tests, we can only use default MTU 1500, changing MTU causes the system not functional(Compute nodes can't ping each other via Zeta after trying MTU change), current Zeta is not robust as we experinced inconsistent behaviour from time to time, both in terms of functionality and performance;
    * For comparision purpose, we tried Arion DP with literally all zeta functionalities added, the throughput can reach to about 4.0Gbps(MTU 1500), this is 33% difference, newer libbpf as well as Linux kernel optimization are the main reasons for the performance increase;
    * Arion DP reaches about 5.0Gbps(MTU 1500), which is another 33% increase in throughput; this is caused by removing unnecessary functionalities and other minor optimizations;
    * Arion DP with driver mode reaches 5.3x Gbps(MTU 1500), a 7% increase;
    * For benchmarking purpose, we can set MTU to 9000 in Arion DP cluster, this boosts the single wing throughput to 9.6Gbps.

 - XDP/eBPF program needs to be carefully written with performance concern in mind, we've seen obvious performance difference in above analysize, as the scenerios Arion DP face become more complex, how careful XDP/eBPF is written matters.


## The Throughput Benchmark 

Netperf TCP throughput metric measures the maximum data transfer rate between containers running on different nodes, which is the *netperf*'s default test. 

![tcp_stream](https://user-images.githubusercontent.com/83482178/190526725-cbf519fb-b2e4-45c5-aed0-fc7da035496a.png)


The above graph shows the maximum throughput that can be achieved with a single TCP connection. With MTU set as 9000, both Node to Node and via Arion reaches about *9.6* Gbps for 10G Nic interface with across Arion has slight higher throughput(*+2.5%*); With default MTU(1500), via arion and direct reaches about the same throughput; driver mode reaches *5.2%* higher throughput while turning on direct path OAM downgrades throughput by *15%*. 

| Config	 | MTU	  | Througphut(Mbps) | Difference(%) |  Retrans/s |
| :---       | :---:  | :---:            |          ---: |     ---: |
| Zeta    	 |	1500  |	3073.6          | 	  61.1%      |   370.81 |
| DP OAM on  |	1500  |	4275.28 		   |    85.0%      |     90.57  |
| via Arion	 |	1500  |	4995.24          | 	  99.3%      |   95.82  |
| drv mode	 |	1500  |	5292.14 	     |	  105.2%     |     0.02   |
| direct	 |  1500  |	5031.76 		 |    100%       |         0.00   |
|          |        |             |                |                | 
| via Arion  |	9000  |	9586.03 		 |    101.7%     |       17.07  |
| direct	 |  9000  |	9426.22 		 |    100%       |         26.23  |

The tests are measured by running *netperf* using the *TCP_STREAM* test. Since the test is mostly done using a single core for network processing(as also observed during the test), for default mtu 1500 tests, above number is constrained by the available CPU resources of a single core. An interesting observation is XDP/eBPF driver mode has noticable better throughput than direct. It looks like longer data pipeline helps here. This can be further studied but not the focus for now.

TCP throughput benchmark is extreamly useful for applications like:
 - AL/ML applications which requre access to large amount of data;
 - Media streaming services.

## Latency: Requests per Second
The request per second metric measures the rate of single byte round-trips that can be performed in sequence over a single persistent TCP connection. It can be thought of as a user-space to user-space ping with no think time - it is by default a synchronous, one transaction at a time, request/response test.
This benchmark highlights how effeciently a single network packet can be processed.


![tcp_rr1](https://user-images.githubusercontent.com/83482178/180340898-7cf17a41-8deb-4814-a5e4-6d4cdf17b50a.png)

![tcp_rr2](https://user-images.githubusercontent.com/83482178/180340959-704dc546-8961-4094-8dbe-fb6d901fb724.png)



## Latency: Rate of new Connections
This test measures the performance of establishing a connection, exchanging a single request/response transaction, and tearing-down that connection. This is very much like what happens in an HTTP 1.0 or HTTP 1.1 connection when HTTP Keepalives are not used.

![tcp_crr1](https://user-images.githubusercontent.com/83482178/180341014-5b09cb38-8baa-4fe0-b2e1-47a12bc3a2a3.png)

![tcp_crr2](https://user-images.githubusercontent.com/83482178/180341154-4bc03a36-c650-4fd6-8c1f-7bcfc4209cdd.png)

## Redis Benchmarking

### Throughput(Request/s)
To experiement how well application may run across Arion DP cluster, we run standard redis benchmarking tool on Compute Nodes and compare the performance between direct compute node to compute node and via Arion DP cluster. With redis server run on one of the containers in compute node, redis benchmarking application is launched from another container in different computer node with two sets of benchmarking tests. 
  - On one container, launch redis server with command:
    - *redis-server --protected-mode no*
  - On another container on different compute node, we launch redis benchmarking commands:
    - *redis-benchmark -h {server_ip}*;
      - default parameters:  
        - 100000 requests
        - 50 parallel clients
        - 3 bytes payload
        - keep alive: 1
    - *redis-benchmark -h {server_ip} -d 1400 -P 50*.  We use larger packet size and turn on pipeline for better throughput.
      - new parameters:
        - 100000 requests
        - 50 parallel clients
        - 50 pipeline requests
        - 1400 bytes in payload
        - keep alive: 1
    
![redis-default](https://user-images.githubusercontent.com/83482178/190533358-1adc3172-8317-4670-b119-7460478199ff.png)
![redis-pipe1](https://user-images.githubusercontent.com/83482178/190533462-3c3911ff-3216-49ad-941e-22b0050c1b0f.png)
![redis-pipe2](https://user-images.githubusercontent.com/83482178/190533523-94160e99-20b2-4156-a9d2-b23c901e9c4a.png)

| Test	    | default direct(req/s) |	default via arion(req/s) |	difference(%)	| pipelined direct(req/s) |	pipelined via arion(req/s) | difference(%) |
| :---      | :---:          | :---:              |         :---: |     :---:         |  :---:              | ---:         |
| PING_INLINE	| 38789.76 |	37271.71 |	96.09% |	548087.44	| 566101.69 |  103.29%   |	
| PING_BULK	 | 43122.04	| 36751.20	| 85.23%	|952857.19	| 1123595.50 | 117.92% |	
| SET	| 44072.28	| 38580.25|	87.54%	| 237283.69 |	245183.38	| 103.33% |
| GET	| 47961.63	|38744.67	| 80.78%	| 251788.94	|238095.25	| 94.56% |
| INCR	| 47915.67|	38491.14 |	80.33%|	676013.50	|648064.50	| 95.87% |
| SADD	| 45724.73|	39385.59 |	86.14% | 	557777.75	|595238.12	| 106.72% |
| ZADD	| 40355.12|	38789.76 | 96.12%	|418410.06	|449103.12	| 107.34% |
| ZPOPMIN	| 39231.07|	38565.37 | 98.30%	|	674832.19	|766030.56	| 113.51% |
| LRANGE_100| 23523.88 |	23148.15 |	98.40%|	2491.48|	3145.00	| 126.23% |
| LRANGE_600|	5667.97	| 5596.91	| 98.75% |	409.42	|496.99	| 121.39% |


### Latency
The earlier version of redis-benchmark has latency and throughput in summary output but the later version only has requests/s output: requests/s and request time distribution. We also used "redis-cli --latency" to compare the average latency between direct and via arion. For redis application, via arion adds about *0.1ms* in latency in avarage.

For direct:

root@4b66c0f71492:/# redis-cli --latency-history -h 123.0.0.178

  *min: 0, max: 1, avg: 0.28 (1445 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.25 (1448 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.29 (1444 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.25 (1446 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.27 (1446 samples) -- 15.00 seconds range*

  *min: 0, max: 1, avg: 0.27 (1445 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.26 (1447 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.26 (1445 samples) -- 15.00 seconds range*

  *min: 0, max: 1, avg: 0.28 (1444 samples) -- 15.00 seconds range*

For via arion:

root@4b66c0f71492:/etc/redis# redis-cli --latency-history -h 123.0.0.178   

  *min: 0, max: 1, avg: 0.37 (1429 samples) -- 15.00 seconds range*

  *min: 0, max: 1, avg: 0.39 (1428 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.37 (1432 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.38 (1429 samples) -- 15.00 seconds range*

  *min: 0, max: 1, avg: 0.39 (1429 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.36 (1430 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.37 (1428 samples) -- 15.01 seconds range*

  *min: 0, max: 1, avg: 0.37 (1430 samples) -- 15.01 seconds range*

  *min: 0, max: 3, avg: 0.35 (1429 samples) -- 15.00 seconds range*

### Notes 

[Redis commands explanation](https://redis.io/commands/)