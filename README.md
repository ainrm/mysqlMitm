## mitm - mysql流量劫持



### 0x01 简介

一个使用 gopacket 实现的 mysql 流量劫持工具，适用于中间人场景，通过发送 `LOAD DATA LOCAL`返回包来读取任意客户端文件，搭配合适的利用链，可能形成漏洞利用进一步触发命令执行，相关的过程记录在 [这里](https://ainrm.cn/2025/mysqlMitm.html)



### 0x02 使用说明

```bash
# go run main.go -h

Usage of main:
  -de string
        网卡名 (default "eth0")
  -file string
        待读取文件 (default "/etc/passwd")
  -sql string
        待劫持sql语句 (default "select 1")
```



