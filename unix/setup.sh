sudo nft add table inet filter
sudo nft 'add chain inet filter input { type filter hook input priority 0 ; }'
sudo nft 'add chain inet filter output { type filter hook output priority 0 ; }'

sudo nft add rule inet filter input  ip saddr { 10.0.0.0/8, 255.255.255.255 } ip protocol icmp         queue num 472 bypass
sudo nft add rule inet filter output ip daddr { 10.0.0.0/8, 255.255.255.255 } ip protocol { tcp, udp } queue num 472 bypass

sudo nft add rule inet filter input  ip6 saddr { 2001:da8:2029::/48, ff00::/8 } ip6 nexthdr icmpv6       queue num 472 bypass
sudo nft add rule inet filter output ip6 daddr { 2001:da8:2029::/48, ff00::/8 } ip6 nexthdr { tcp, udp } queue num 472 bypass