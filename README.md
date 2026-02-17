# Diameter-parser

<img width="333" height="325" alt="diam-p" src="https://github.com/user-attachments/assets/8237939c-50a8-4587-9cfe-40c96dda0baa" />


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

NOTE: Each Diameter message found in the capture is emitted as a JSON object on stdout.
