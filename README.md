ss(r)Sniff
-------

Yet another proof of concept of detecting SS(R) traffic. Forked from https://github.com/isofew/sssniff.

It's a demonstration that SS(R) is vulnerable to traffic analysis.

It also shows detecting SSR with traffic analysis is much cheaper than SS, as well as has a much smaller false positive
rate.

### How it works?

It computes entropy of the first 32 packet lengths of each TCP connection. When the entropy is larger than a threshold, the
connection is detected as a SSR connection.

### Why it works?

The traffic of SS(R) looks randomized with a relative high entropy of the first 2 to 3 packets. As a result, SS(R) can be detected by computing the entropy of these packets. The drawback is this approach shows high false positive rate and is very expensive.

Besides randomizing traffic, SSR also randomizes the packet lengths, which would cause many packets smaller than MTU. By
computing the entropy of the packet lengths, the connection can be detected easily. Without computing the entropy of
whole packets, detecting SSR requires much less computing power.

ssSniff
------
ShadowSocks(SS) traffic sniffer

### Aim
Proof of concept of detecting SS traffic. Could be used for the improvement of SS. Or, for the censorship against SS. Either way, it is better to expose the vulnerabilities in advance and take the initiative.

### Usage
```
# install libpcap first, then
pip install -r requirements.txt
sudo ./sssniff.py
```
Finally, browse the web via your SS proxy. When the script detects more than 15 suspicious connections to/from one source, it will flag it to be a ShadowSocks server and print to the terminal.

### Method
ShadowSocks is famous for its randomness feature; however, the first packet of a connection is usually not expected to be random. Even in a TLS session, we expect to see some plaintext sections in the handshake stage. Therefore, one can detect ShadowSocks traffic by simply looking at the first few packets and calculating their entropy (as a measure of randomness). Together with some minor adjustments, this method suffices to detect the current ShadowSocks protocol at a high accuracy.

### TODO
* Develop a more general method to detect proxy traffic.
* Test for false-positive results.

### Credits
* [scapy](http://www.secdev.org/projects/scapy/) for packet sniffing/manipulation
* [dpkt](https://github.com/kbandla/dpkt) for packet parsing/creation
