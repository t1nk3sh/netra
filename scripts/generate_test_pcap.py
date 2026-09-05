"""Generate synthetic PCAPs for testing."""

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Ether, Raw, wrpcap

PCAP_PATH = "data/samples/test_traffic.pcap"
ZEEK_PCAP_PATH = "data/samples/zeek_test_traffic.pcap"


def generate() -> str:
    packets = []
    base_time = 1700000000.0

    for i in range(5):
        pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.1") / TCP(
            sport=12345 + i, dport=80, flags="S"
        )
        pkt.time = base_time + i * 0.1
        packets.append(pkt)

    for i in range(3):
        pkt = Ether() / IP(src="10.0.0.2", dst="192.168.1.2") / UDP(
            sport=5000, dport=53
        ) / DNS(rd=1, qd=DNSQR(qname=f"test{i}.example.com"))
        pkt.time = base_time + 0.5 + i * 0.2
        packets.append(pkt)

    pkt = Ether() / IP(src="10.0.0.3", dst="192.168.1.3") / TCP(
        sport=9999, dport=443, flags="SA"
    )
    pkt.time = base_time + 1.5
    packets.append(pkt)

    pkt = Ether() / IP(src="10.0.0.4", dst="192.168.1.4") / TCP(
        sport=8080, dport=8443, flags="PA"
    )
    pkt.time = base_time + 2.0
    packets.append(pkt)

    wrpcap(PCAP_PATH, packets)
    return PCAP_PATH


def generate_zeek_pcap() -> str:
    """Generate a richer PCAP that produces conn.log, dns.log from Zeek."""
    packets = []
    base_time = 1700000000.0

    syn = Ether() / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(
        sport=50000, dport=80, flags="S", seq=1000
    )
    syn.time = base_time
    packets.append(syn)

    sa = Ether() / IP(src="93.184.216.34", dst="10.0.0.1") / TCP(
        sport=80, dport=50000, flags="SA", seq=2000, ack=1001
    )
    sa.time = base_time + 0.01
    packets.append(sa)

    ack = Ether() / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(
        sport=50000, dport=80, flags="A", seq=1001, ack=2001
    )
    ack.time = base_time + 0.02
    packets.append(ack)

    data = Ether() / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(
        sport=50000, dport=80, flags="PA", seq=1001, ack=2001
    ) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    data.time = base_time + 0.03
    packets.append(data)

    resp = Ether() / IP(src="93.184.216.34", dst="10.0.0.1") / TCP(
        sport=80, dport=50000, flags="PA", seq=2001, ack=1041
    ) / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
    resp.time = base_time + 0.05
    packets.append(resp)

    fin1 = Ether() / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(
        sport=50000, dport=80, flags="FA", seq=1041, ack=2046
    )
    fin1.time = base_time + 0.1
    packets.append(fin1)

    fin2 = Ether() / IP(src="93.184.216.34", dst="10.0.0.1") / TCP(
        sport=80, dport=50000, flags="FA", seq=2046, ack=1042
    )
    fin2.time = base_time + 0.11
    packets.append(fin2)

    for i, domain in enumerate(["example.com", "test.org", "suspicious.xyz"]):
        query = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(
            sport=50100 + i, dport=53
        ) / DNS(rd=1, qd=DNSQR(qname=domain))
        query.time = base_time + 0.2 + i * 0.1
        packets.append(query)

        response = Ether() / IP(src="8.8.8.8", dst="10.0.0.1") / UDP(
            sport=53, dport=50100 + i
        ) / DNS(
            qr=1, aa=1, qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, rdata=f"1.2.3.{i + 1}")
        )
        response.time = base_time + 0.21 + i * 0.1
        packets.append(response)

    for i in range(5):
        pkt = Ether() / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(
            sport=50200 + i, dport=443, flags="S", seq=3000 + i
        )
        pkt.time = base_time + 0.6 + i * 0.05
        packets.append(pkt)

    wrpcap(ZEEK_PCAP_PATH, packets)
    return ZEEK_PCAP_PATH


if __name__ == "__main__":
    path = generate()
    print(f"Generated {path}")
    path2 = generate_zeek_pcap()
    print(f"Generated {path2}")
