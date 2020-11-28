# sce

This is the [SCE](https://datatracker.ietf.org/doc/draft-morton-tsvwg-sce/)
(Some Congestion Experienced) reference implementation, containing:

- the new TCP CC algorithms reno-sce, dctcp-sce and cubic-sce
- changes to TCP input for SCE to ESCE feedback
- changes to the Cake qdisc for SCE signaling
- additional qdiscs under testing: twin_codel_af, cnq_codel_af, cnq_cobalt,
  lfq_cobalt

## Status

The CC algorithms are all working, but may need subtle tweaks.

The various qdiscs in development are experiments with how to improve the
deployability of SCE in a small number of queues. While flow isolation and
fairness is straightforward with FQ, mechanisms for achieving both without FQ
are still under research. Possibilities include approximate fairness (see "af"
qdiscs and
[CodelAF](https://tools.ietf.org/html/draft-morton-tsvwg-codel-approx-fair-01)),
DSCP, flow-aware queue selection, or queueing algorithms that do not
adhere to strict FIFO semantics such as
[LFQ](https://tools.ietf.org/html/draft-morton-tsvwg-lightweight-fair-queueing-00).

We welcome any problem reports as
[Issues](https://github.com/chromi/sce/issues) on this repo.

## Compiling the kernel

Compile the Linux kernel as usual, making sure to include the new CC algorithms
in the config (under Networking support > Networking options > TCP: advanced
congestion control) and the SCE qdiscs (under Networking support >
Networking options > QoS and/or fair queueing). Here's a quick overview of a
typical way to do this:

```
sudo apt-get install build-essential libncurses-dev libssl-dev
git clone https://github.com/chromi/sce
cd sce
make menuconfig # configure kernel, include all TCP CC algos and Cake
make -j $(nproc)
make modules
sudo make modules_install
sudo make install
sudo reboot
```

## Compiling iproute2

New qdiscs and parameters are added which require changes to the tc binary.
Below are the commands that may be used to compile and install the updated tc.

```
sudo apt-get install pkg-config bison flex libcap-dev libmnl-dev libelf-dev libdb-dev
git clone https://github.com/heistp/iproute2-sce
cd iproute2-sce
./configure
make
# use the resulting tc/tc binary when working with SCE qdiscs
```

## Sysctls

By default, SCE is not enabled. The following sysctls may be used to control
the operation of SCE and related functionality:

- `net.ipv4.tcp_sce` - set to 1 to feed back SCE to ESCE (for receivers)
- `net.ipv4.tcp_ecn` - set to 1 to enable ECN during connection initiation
  (for senders)
- `net.ipv4.ip_forward` - set to 1 to enable IP forwarding, e.g. on middleboxes
  running Cake
- `net.ipv4.tcp_congestion_control` - set to one of reno-sce, dctcp-sce or
  cubic-sce to default all TCP connections to use this CC algorithm, although
  setting it explicitly for individual test flows may be the preferred method

## Cake and its SCE related parameters

To test SCE, a bottleneck and SCE marking are needed between the TCP sender and
receiver. As an example, the Cake qdisc from this kernel must be used at the
bottleneck. Cake's shaper is used to restrict bandwidth and create a bottleneck,
then Cake can be configured to do SCE marking, which will mark IP packets with
SCE as queue sojourn times increase. An example invocation of Cake is as
follows:

```
tc qdisc add dev enp1s0 root cake besteffort bandwidth 10Mbit sce
```

Replace enp1s0 with your interface and 10Mbit with your bandwidth. On a
middlebox with two interfaces, you may want Cake applied on both interfaces.
The `sce` parameter tells Cake to do SCE marking. The following additional
parameters may be used to control the operation of SCE:

- `sce-single` - maximally prefers SCE vs non-SCE fairness over early SCE
  signaling.
- `sce-thresh #` - where # is a number from 1-1024, with 1 being equivalent
  to `sce`, and 1024 being nearly equivalent to `sce-single`. This balances SCE
  vs non-SCE throughput fairness with earlier SCE signaling. Numbers around 20
  may yield a reasonable balance for 50Mbit at 80ms for reno vs reno-sce
  competition, for example.

## Testing

A full explanation of the testing options is beyond the scope of this
document, but for starters, one might wish to initiate a simple test of a
single flow using iperf3. Here's an example using reno-sce, and note that
root is required to explicitly set the TCP CC algorithm.

```
sudo iperf3 -C reno-sce -c server
```

The [Flent](https://flent.org) tool, which has the ability to run tests with
different CC algorithms, may be used for single and multi-flow tests along
with latency measurement flows.

A tool called `scetrace` has been implemented that uses libpcap to record
per-flow SCE and related statisics from either pcap files or live captures.
This is available [here](https://github.com/heistp/scetrace).

Test repositories [here](https://github.com/heistp/sce-l4s-bakeoff) and
[here](https://github.com/heistp/sce-l4s-ect1) include flent batch files
and a surrounding test harness to run various tests of SCE, and also L4S.

## Feedback branch

There is a separate branch called `feedback` on which is an implementation of a
different receiver feedback algorithm called "dithered" feedback, which is
still undergoing testing. It trades off less timely ESCE marked ACKs for a
reduction in ACKs on the ACK path back to the TCP standard of 50%, whereas
around 60% is expected with the default algorithm. The sysctl
`net.ipv4.tcp_sce_feedback` controls which algorithm is used, with 1 meaning
the default algorithm (and is the default), and 0 meaning dithered feedback.
