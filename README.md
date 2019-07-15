# dockervpp
A docker network plugin for interfacing w/ VPP

Thanks @araxus for bootstrapping the driver code.

## **Current Network Topology**
```
//
// +------------------------------------------+                                        +-------------------------------------------+
// |                  DOCKER                  |                                        |                    DOCKER                 |
// |                                          |                                        |                                           |
// +-----------------------+                  |                                        +-----------------------+                   |
// |                       |                  |                                        |                       |                   |
// |      Vera Peer 1      <-------+          |                                        |      Vera Peer 2      <--------+          |
// |                       |       |          |                                        |                       |        |          |
// +-----------------------+       |          |                                        +-----------------------+        |          |
// |                               |          |                                        |                                |          |
// |                               |          |                                        |                                |          |
// |                               |          |                                        |                                |          |
// |                               |          |                                        |                                |          |
// |                             +-v------+   |                                        |                              +-v-------+  |
// |                             |        |   |                                        |                              |         |  |
// |                             |  VETH  |   |                                        |                              |  VETH   |  |
// |                             |        |   |                                        |                              |         |  |
// |                             +------^-+   |                                        |                              +-------^-+  |
// +------------------------------------------+                                        +-------------------------------------------+
//                                      |                                                                                     |
//        +-----------------------------+                                                                                     |
//        |                                                                                                                   |
// +---------------------------------------+--------+                               +--------+-------------------------------------+
// |      |                                |        |                               |        |                                |    |
// | +----v--+-----------+---------+       |        |                               |        |       +---------+---------+----v--+ |
// | |       |           |         |       |        |                               |        |       |         |         |       | |
// | | VHOST <-----------> BVI GWY <------->  DPDK  <------------------------------->  DPDK  <-------> BVI GWY <---------> VHOST | |
// | |       |  L2   BD  |         |       |        |                               |        |       |         | L2   BD |       | |
// | +-----------------------------+       |        |                               |        |       +---------------------------+ |
// +---------------------------------------+--------+                               +--------+-------------------------------------+
```

## **TODO: Use VCL (when it's stable) to bypass the kernel completely and use the TCP host stack on VPP through the memif interface**
```
// 
// +------------------------------------------+                                        +-------------------------------------------+
// |                  DOCKER                  |                                        |                   DOCKER                  |
// |                                          |                                        |                                           |
// +-----------------------+                  |                                        +-----------------------+                   |
// |                       |                  |                                        |                       |                   |
// |      Vera Peer 1      <-------+          |                                        |      Vera Peer 2      <--------+          |
// |                       |       |          |                                        |                       |        |          |
// +-----------------------+       |          |                                        +-----------------------+        |          |
// |                               |          |                                        |                                |          |
// |                               |          |                                        |                                |          |
// |                               |          |                                        |                                |          |
// |                               |          |                                        |                                |          |
// |                             +-v------+   |                                        |                              +-v-------+  |
// |                             |        |   |                                        |                              |         |  |
// |                             | VCL-ABI|   |                                        |                              | VCL-ABI |  |
// |                             |        |   |                                        |                              |         |  |
// |                             +------^-+   |                                        |                              +-------^-+  |
// +------------------------------------------+                                        +-------------------------------------------+
//                                      |                                                                                     |
//        +------CIRCULAR BUFFERS-------+                                                                             CIRCULAR BUFFERS
//        |                                                                                                                   |
// +---------------------------------------+--------+                               +--------+-------------------------------------+
// |      |                                |        |                               |        |                                |    |
// | +----v--+-----------+---------+       |        |                               |        |       +---------+---------+----v--+ |
// | |       |           |         |       |        |                               |        |       |         |         |       | |
// | | MEMIF <-----------> BVI GWY <------->  DPDK  <------------------------------->  DPDK  <-------> BVI GWY <---------> MEMIF | |
// | |       |  L2   BD  |         |       |        |                               |        |       |         | L2   BD |       | |
// | +-----------------------------+       |        |                               |        |       +---------------------------+ |
// +---------------------------------------+--------+                               +--------+-------------------------------------+
```