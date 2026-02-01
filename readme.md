# ALL in ICMP

Using icmp to pass though firewall. that is make everything in icmp packet.
We only changed the protocol, not disguised it. Therefore, it may be blocked by stricter firewalls.

Since there is unused bits in IPv4/IPv6, we can distinguish TCP and UDP.


## Broadcast

Now it support to redirect broadcast to specific ip.

## Usage

```sh
sudo ./all-in-icmp-win.exe [IPv4 addr] [IPv6 addr] 
sudo ./all-in-icmp-unix.exe [IPv4 addr] [IPv6 addr] 
```
All broadcast package will be redirected to the address you give.

> Guess what, windows now support `sudo`.
