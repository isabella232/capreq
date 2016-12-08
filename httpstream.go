package capreq

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"net/http"
)

type httpStreamFactory struct {
	cap *Capture
}

type httpStream struct {
	net, transport gopacket.Flow
	reader         tcpreader.ReaderStream
	cap            *Capture
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		reader:    tcpreader.NewReaderStream(),
		cap:       h.cap,
	}

	hstream.reader.LossErrors = true

	go hstream.run()

	return &hstream.reader
}

func (h *httpStream) run() {
	defer h.cap.wg.Done()
	h.cap.wg.Add(1)

	buf := bufio.NewReader(&h.reader)

	for {
		req, err := http.ReadRequest(buf)

		if err == io.EOF {
			break
		}

		if err != nil {
			continue
		}

		if h.cap.requestHandler != nil {
			h.cap.requestHandler(req)
		}
	}
}
