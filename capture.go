package reqcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"net/http"
	"sync"
	"time"
)

const BUFFER_SIZE = 50 * 1024 * 1024
const SNAPSHOT = 65535
const FLUSH_DURATION = 30 * time.Second

type Capture struct {
	requestHandler func(*http.Request)
	handle         *pcap.Handle
	wg             *sync.WaitGroup
}

func FromFile(file string) (*Capture, error) {
	handle, err := pcap.OpenOffline(file)

	if err != nil {
		return nil, err
	}

	cap := &Capture{
		handle: handle,
	}

	return cap, nil
}

func FromInterface(iface string, snaplen int, bufSize int, filter string) (*Capture, error) {
	ihandle, err := pcap.NewInactiveHandle(iface)
	defer ihandle.CleanUp()

	if err != nil {
		return nil, err
	}

	err = ihandle.SetSnapLen(snaplen)
	err = ihandle.SetImmediateMode(true)
	err = ihandle.SetBufferSize(bufSize)

	if err != nil {
		return nil, err
	}

	handle, err := ihandle.Activate()

	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter(filter)
	err = handle.SetDirection(pcap.DirectionIn)

	if err != nil {
		return nil, err
	}

	cap := &Capture{
		handle: handle,
	}

	return cap, nil
}

func FromPort(port int) (*Capture, error) {
	filter := fmt.Sprintf("tcp and port %d", port)
	return FromInterface("any", SNAPSHOT, BUFFER_SIZE, filter)
}

func (c *Capture) HandleRequest(fn func(*http.Request)) {
	c.requestHandler = fn
}

func (c *Capture) Start() {
	defer c.handle.Close()

	c.wg = &sync.WaitGroup{}

	streamFactory := &httpStreamFactory{cap: c}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Second)

loop:
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				break loop
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}

			tcp := packet.TransportLayer().(*layers.TCP)

			if len(tcp.Payload) == 0 {
				continue
			}

			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(-1 * FLUSH_DURATION))
		}
	}

	assembler.FlushAll()

	c.wg.Wait()
}
