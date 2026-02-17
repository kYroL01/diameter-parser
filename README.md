# diameter-parser

Diameter protocol parsing tool

## Build

Prerequisites:
- Go 1.24+
- libpcap headers (e.g., `sudo apt-get install -y libpcap-dev` on Debian/Ubuntu)

Build the binary:

```bash
go build -o diameter-parser .
```

## Run

Provide a PCAP file with Diameter traffic and point the binary at it:

```bash
./diameter-parser -pcap path/to/capture.pcap
```

Each Diameter message found in the capture is emitted as a JSON object on stdout. You can also run without building a standalone binary by using `go run . -pcap <file>`.
