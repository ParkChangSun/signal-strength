package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wcharczuk/go-chart"
)

type RadioTap struct {
	Header       uint16
	HeaderLength uint16
	PresentFlags uint32
	TxFlags      uint16
	DataRetries  uint8
}

type Dot11 struct {
	Type            uint16
	Duration        uint16
	DestinationAddr [6]byte
	SourceAddr      [6]byte
	BssId           [6]byte
	FragSeq         uint16
}

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func ExecutingBar(content string) {
	bar := "|/-\\"
	seq := 0
	for {
		fmt.Printf("Executing %s ... %s\r", content, string(bar[seq]))
		seq++
		seq %= len(bar)
		time.Sleep(time.Second / 10)
	}
}

func AddrToBytes(addr string) ([6]byte, error) {
	res := [6]byte{}
	slice := strings.Split(addr, ":")
	if len(slice) != 6 {
		return res, fmt.Errorf("wrong addr format : %s", addr)
	}
	for i, h := range slice {
		b, err := hex.DecodeString(h)
		if err != nil {
			return res, err
		}
		res[i] = b[0]
	}
	return res, nil
}

func main() {
	// ifSelect := os.Args[1]
	// handler, err := pcap.OpenLive(ifSelect, 2048, true, pcap.BlockForever)
	handler, err := pcap.OpenOffline("dot11-sample.pcap")
	PanicError(err)

	// var radioTap layers.RadioTap
	// var dot11 layers.Dot11

	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeRadioTap, &radioTap, &dot11)
	// decoded := []gopacket.LayerType{}

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		radioTapLayer := packet.Layer(layers.LayerTypeRadioTap)
		radioTap := radioTapLayer.(*layers.RadioTap)
		fmt.Printf("radioTap.DBMAntennaSignal: %v\n", radioTap.DBMAntennaSignal)

		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		dot11 := dot11Layer.(*layers.Dot11)
		fmt.Printf("dot11.Address3: %v\n", dot11.Address3)
	}

	graph := chart.Chart{
		Series: []chart.Series{
			chart.ContinuousSeries{
				XValues: []float64{1.0, 2.0, 3.0, 4.0},
				YValues: []float64{1.0, 2.0, 3.0, 4.0},
			},
		},
	}

	buffer := bytes.NewBuffer([]byte{})
	err = graph.Render(chart.PNG, buffer)
}
