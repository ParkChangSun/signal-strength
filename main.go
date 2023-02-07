package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/guptarohit/asciigraph"
	"golang.org/x/term"
)

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func main() {
	ifSelect := os.Args[1]
	handler, err := pcap.OpenLive(ifSelect, 2048, true, pcap.BlockForever)
	// handler, err := pcap.OpenOffline("dot11-sample.pcap")
	PanicError(err)

	width, height, err := term.GetSize(0)
	PanicError(err)

	data := []float64{}

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		dot11 := dot11Layer.(*layers.Dot11)
		if dot11.Address3.String() != os.Args[2] {
			continue
		}

		radioTapLayer := packet.Layer(layers.LayerTypeRadioTap)
		radioTap := radioTapLayer.(*layers.RadioTap)
		data = append(data, float64(radioTap.DBMAntennaSignal))

		graph := asciigraph.Plot(data, asciigraph.Width(width-10), asciigraph.Height(height-4))
		fmt.Print("\x1B[1J")
		fmt.Println(graph)
		fmt.Printf("Device %s\nSignal Strength %v\n", dot11.Address3.String(), radioTap.DBMAntennaSignal)
	}
}
