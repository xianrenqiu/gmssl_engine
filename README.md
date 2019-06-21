## gmssl engine

> ! 如果出现找不到引擎的错误, 需要通过 `export OPENSSL_ENGINES=<gmssl_engine>/ext/gmssl/lib/engines-1.1/` 设置环境变量

### 编译与运行
```
$ mkdir build && cd build
$ cmake ..
$ make install
# 查看 gmssl_engine 所支持的算法
$ ./ext/gmssl/bin/gmssl engine -t -c libgmssl_engine
# 输出
Bind gmssl_engine.
(libgmssl_engine) Reference implementation of gmssl crypto engine
 [AES-128-ECB, AES-128-CBC, AES-128-CTR, AES-192-ECB, AES-192-CBC, AES-192-CTR, AES-256-ECB, AES-256-CBC, AES-256-CTR, id-aes128-GCM, id-aes256-GCM, SMS4-ECB, SMS4-CBC, SMS4-CTR, id-ecPublicKey, TLS1-PRF]
     GmSSL Engine initialization:
[ available ]
---- Destroying Engine...
```

### 同步模式测试 sms4-cbc 速度
```
$ ./ext/gmssl/bin/gmssl speed -elapsed -evp sms4-cbc -engine libgmssl_engine
# 输出
Bind gmssl_engine.
GmSSL Engine initialization:
engine "libgmssl_engine" set.
You have chosen to measure elapsed time instead of user CPU time.
Doing sms4-cbc for 3s on 16 size blocks: 4959033 sms4-cbc's in 3.00s
Doing sms4-cbc for 3s on 64 size blocks: 1540008 sms4-cbc's in 3.00s
Doing sms4-cbc for 3s on 256 size blocks: 399877 sms4-cbc's in 3.00s
Doing sms4-cbc for 3s on 1024 size blocks: 106898 sms4-cbc's in 3.00s
Doing sms4-cbc for 3s on 8192 size blocks: 13407 sms4-cbc's in 3.00s
Doing sms4-cbc for 3s on 16384 size blocks: 6530 sms4-cbc's in 3.00s
GmSSL 2.4.2 - OpenSSL 1.1.0d  25 Dec 2018
built on: reproducible build, date unspecified
options:bn(64,64) rc4(16x,int) des(int) aes(partial) idea(int) blowfish(ptr)
compiler: /usr/bin/cc -DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_THREADS -DOPENSSL_NO_DYNAMIC_ENGINE -DOPENSSL_PIC -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DPADLOCK_ASM -DGMI_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/root/share/repo/gmssl_engine/build/../ext/gmssl/ssl\"" -DENGINESDIR="\"/root/share/repo/gmssl_engine/build/../ext/gmssl/lib/engines-1.1\""  -Wa,--noexecstack
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
sms4-cbc         26448.18k    32853.50k    34122.84k    36487.85k    36610.05k    35662.51k
---- Destroying Engine...
```

### 异步模式测试 ecdsa256 速度
```
$ ./ext/gmssl/bin/gmssl speed -engine libgmssl_engine -elapsed -async_jobs 2 ecdsap256
# 输出
Bind gmssl_engine.
GmSSL Engine initialization:
engine "libgmssl_engine" set.
You have chosen to measure elapsed time instead of user CPU time.
Doing 256 bit sign ecdsa's for 10s: 76383 256 bit ECDSA signs in 10.00s
Doing 256 bit verify ecdsa's for 10s: 50811 256 bit ECDSA verify in 10.00s
GmSSL 2.4.2 - OpenSSL 1.1.0d  25 Dec 2018
built on: reproducible build, date unspecified
options:bn(64,64) rc4(16x,int) des(int) aes(partial) idea(int) blowfish(ptr)
compiler: /usr/bin/cc -DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_THREADS -DOPENSSL_NO_DYNAMIC_ENGINE -DOPENSSL_PIC -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DPADLOCK_ASM -DGMI_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/root/share/repo/gmssl_engine/build/../ext/gmssl/ssl\"" -DENGINESDIR="\"/root/share/repo/gmssl_engine/build/../ext/gmssl/lib/engines-1.1\""  -Wa,--noexecstack
                              sign    verify    sign/s verify/s
 256 bit ecdsa (nistp256)   0.0001s   0.0002s   7638.3   5081.1
---- Destroying Engine...

```