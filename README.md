## Prerequisite

Followings are expected to be installed under /usr/local:

* DPDK 16.11.0 or later

## How to build

```
% go install
```

## How to test

```
% ./test.sh
```

This creates the following settings and starts vsw:

```
+---------------------------------+   +--------NS0--------------+
|      bridge0/if0-0 (tap) - veth0 ---veth1    172.16.110.10/24 |
|        |                        |   +-------------------------+
|       vrf1                      |
|        |                        |   +--------NS1--------------+
|      bridge1/if1-0 (tap) - veth2 ---veth3    10.10.0.10/24    |
|                                 |   +-------------------------+
| POC                             |
|                                 |   +--------NS2--------------+
|      bridge2/if2-0 (tap) - veth4 ---veth5    172.16.210.10/24 |
|        |                        |   +-------------------------+
|       vrf2                      |
|        |                        |   +--------NS3--------------+
|      bridge3/if3-0 (tap) - veth6 ---veth7    10.20.0.10/24    |
+---------------------------------+   +-------------------------+
```
To terminate vsw:

```
% sudo killall vsw
```

To disable verbose logging remove '-v' from the option of vsw.

## Examples

Ping from NS1 to NS0 via vsw:
```
% sudo ip netns exec NS1 ping 172.16.110.10
```

## Notes

When writing a module composed from Go and C, do not place
sources in C as the same directry as Go. Put C sources under
sub-directory. Otherwise, go build system tries to build
C source.
