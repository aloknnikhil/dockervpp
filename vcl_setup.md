# **VCL (VPP Communication Library)**

### **Run server/client w/ LD_PRELOAD**
```
export LD_PRELOAD=/lib/x86_64-linux-gnu/libvcl_ldpreload.so
```

### **Setup VCL w/ conf - /etc/vpp/vcl.conf**
```
vcl {
  heapsize 1024M
  rx-fifo-size 4000000
  tx-fifo-size 4000000
  app-scope-global
  app-scope-local
  api-socket-name /var/run/vpp/vpp-api.sock
}
```

### **Setup VPP to support the Host Stack - Add to startup.conf**
```
session { 
  evt_qs_memfd_seg
}
```

### **You should see this**
```
➜ vppctl sh session verbose
Connection                                        State          Rx-f      Tx-f      
[0:0][CT:T] 0.0.0.0:1338->0.0.0.0:0               LISTEN         0         0         
[0:1][T] 0.0.0.0:1338->0.0.0.0:0                  LISTEN         0         0         
[0:0][CT:T] 0.0.0.0:1339->0.0.0.0:0               LISTEN         0         0         
[0:3][T] 0.0.0.0:1339->0.0.0.0:0                  LISTEN         0         0         
[0:0][CT:T] 0.0.0.0:1441->0.0.0.0:0               LISTEN         0         0         
[0:5][T] 0.0.0.0:1441->0.0.0.0:0                  LISTEN         0         0         
Thread 0: active sessions 6

Connection                                        State          Rx-f      Tx-f      
[1:7][T] 5.0.0.1:1441->5.0.0.101:61600            ESTABLISHED    0         0         
Thread 1: active sessions 1 closed 7
Thread 2: no sessions

Connection                                        State          Rx-f      Tx-f      
Thread 3: active sessions 0 closed 2
```