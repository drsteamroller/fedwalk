# Example run of fedwalk.py

This is how the program was run:

```
py fedwalk.py .\Example\Usage 0 -sPIP -st=replaceSTRs.txt
```

In sslvpn_debug.txt, you can see the replaced "Magic Number" values that were specified in the replaceSTRs.txt replacement. Additionally, you can see that the routing table entries got screwed up, which is something I'm currently working on.

Glance through the two documents, and you'll see a consistent replacement of IP addresses and the Magic Numbers in sslvpn_debugs.txt