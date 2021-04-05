import struct
import sys
import statistics


def format_timestamp(time):
    m = int(time % 3600 // 60)
    s = time % 3600 % 60
    if m == 0:
        return "{:02f}s".format(s)
    return "{:2d}m {:02f}s".format(m, s)


class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self, dst):
        self.dst_port = dst

    def seq_num_set(self, seq):
        self.seq_num = seq

    def ack_num_set(self, ack):
        self.ack_num = ack

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def flags_set(self, ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self, size):
        self.window_size = size

    def get_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.src_port_set(port)
        return None

    def get_dst_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.dst_port_set(port)
        return None

    def get_seq_num(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.seq_num_set(seq)
        return None

    def get_ack_num(self, buffer):
        ack = struct.unpack(">I", buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.flags_set(ack, rst, syn, fin)
        return None

    def get_window_size(self, buffer1, buffer2):
        buffer = buffer2 + buffer1
        size = struct.unpack("H", buffer)[0]
        self.win_size_set(size)
        return None

    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4) * 4
        self.data_offset_set(length)
        return None

    def relative_seq_num(self, orig_num):
        if self.seq_num >= orig_num:
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)

    def relative_ack_num(self, orig_num):
        if self.ack_num >= orig_num:
            relative_ack = self.ack_num - orig_num + 1
            self.ack_num_set(relative_ack)


class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>
    identification = None
    flags = {}
    fragment_offset = None
    ttl = None
    protocol = None
    icmp_type = None
    icmp_code = None
    icmp_data = None
    udp_src_port = None
    icmp_src_port = None
    icmp_seq_num = None
    udp_seq_num = None

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
        self.identification = None
        self.flags = {}
        self.fragment_offset = None
        self.ttl = None
        self.protocol = None
        self.icmp_type = None
        self.icmp_code = None
        self.icmp_data = None
        self.udp_src_port = None
        self.icmp_src_port = None
        self.icmp_seq_num = None
        self.udp_seq_num = None

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def identification_set(self, value):
        self.identification = value

    def flags_set(self, MF, DF):
        self.flags["MF"] = MF
        self.flags["DF"] = DF

    def fragment_offset_set(self, value):
        self.fragment_offset = value

    def ttl_set(self, value):
        self.ttl = value

    def protocol_set(self, value):
        self.protocol = value

    def udp_src_port_set(self, src):
        self.udp_src_port = src

    def icmp_src_port_set(self, src):
        self.icmp_src_port = src

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack("BBBB", buffer1)
        dst_addr = struct.unpack("BBBB", buffer2)
        s_ip = (
            str(src_addr[0])
            + "."
            + str(src_addr[1])
            + "."
            + str(src_addr[2])
            + "."
            + str(src_addr[3])
        )
        d_ip = (
            str(dst_addr[0])
            + "."
            + str(dst_addr[1])
            + "."
            + str(dst_addr[2])
            + "."
            + str(dst_addr[3])
        )
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack("B", value)[0]
        length = (result & 15) * 4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        length = num1 + num2 + num3 + num4
        self.total_len_set(length)

    def get_identification(self, buffer):
        value = int.from_bytes(buffer, "big")
        self.identification_set(value)

    def get_flags(self, buffer):
        MF = buffer & 32 == 32
        DF = buffer & 64 == 64
        self.flags_set(MF, DF)
        return None

    def get_fragment_offset(self, buffer):
        length = int.from_bytes(buffer, "little") * 8
        self.fragment_offset_set(length)
        return None

    def get_ttl(self, buffer):
        result = struct.unpack("B", buffer)[0]
        self.ttl_set(result)

    def get_protocol(self, buffer):
        result = struct.unpack("B", buffer)[0]
        self.protocol_set(result)

    def get_icmp_code(self, buffer):
        value = struct.unpack('B', buffer)[0]
        self.icmp_code = value

    def get_icmp_type(self, buffer):
        value = struct.unpack('B', buffer)[0]
        self.icmp_type = value

    def get_icmp_data(self, buffer):
        self.icmp_data = buffer

    def get_udp_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.udp_src_port_set(port)
        return None

    def get_icmp_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.icmp_src_port_set(port)
        return None

    def get_icmp_seq_num(self, buffer):
        self.icmp_seq_num = buffer

    def get_udp_seq_num(self, buffer):
        self.udp_seq_num = buffer


class packet:
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    packet_length = 0
    packet_orig_length = 0
    packet_data = None
    buffer = None
    data_length = 0

    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.packet_length = 0
        self.packet_orig_length = 0
        self.data_length = 0

    def timestamp_set(self, buffer1, buffer2, orig_sec, orig_usec):
        secs = struct.unpack("I", buffer1)[0]
        usecs = struct.unpack("<I", buffer2)[0]
        orig_time = orig_sec + orig_usec * 0.000000001
        self.timestamp = round(secs + usecs * 0.000000001 - orig_time, 6)

    def packet_No_set(self, number):
        self.packet_No = number

    def set_packet_length(self, incl_len, orig_len):
        self.packet_length = incl_len
        self.packet_orig_length = orig_len

    def get_data_length(self):
        self.data_length = self.IP_header.total_len - \
            self.IP_header.ip_header_len - self.TCP_header.data_offset

    def get_RTT_value(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)
        return round(rtt, 8)


udp_packets = []
icmp_packets = []
packet_number = 0
orig_sec = None
orig_usec = None
firstPacket = True

connections = []

if(len(sys.argv) != 2):
    print("ERROR: Invalid arguments. SmartParser accepts exactly one argument: the trace file in the same directory to be parsed.")
    sys.exit()

with open(sys.argv[1], "rb") as f:
    global_header = f.read(24)  # We don't do anything with this
    x = 1
    while True:
        # For each packet
        data = f.read(16)
        if not data:
            break
        else:
            # PACKET CONFIG
            p = packet()
            ts_sec = data[0:4]
            ts_usec = data[4:8]
            incl_len = data[8:12]
            orig_len = data[12:16]

            if firstPacket:
                orig_sec = struct.unpack("I", ts_sec)[0]
                orig_usec = struct.unpack("I", ts_usec)[0]
            p.timestamp_set(ts_sec, ts_usec, orig_sec, orig_usec)

            firstPacket = False
            packet_length = struct.unpack("I", incl_len)[0]
            packet_orig_len = struct.unpack("I", orig_len)[0]
            p.set_packet_length(packet_length, packet_orig_len)

            p.packet_No_set(packet_number)
            packet_number = packet_number + 1

            packet_data = f.read(packet_length)

            # IP HEADER
            p.IP_header.get_header_len(packet_data[14:15])
            p.IP_header.get_total_len(packet_data[16:18])

            p.IP_header.get_identification(packet_data[18:20])
            p.IP_header.get_flags(packet_data[20])
            p.IP_header.get_fragment_offset(packet_data[21:22])
            p.IP_header.get_ttl(packet_data[22:23])
            p.IP_header.get_protocol(packet_data[23:24])
            p.IP_header.get_IP(packet_data[26:30], packet_data[30:34])

            if p.IP_header.protocol == 1:
                p.IP_header.get_icmp_type(packet_data[34:35])
                p.IP_header.get_icmp_code(packet_data[35:36])
                p.IP_header.get_icmp_data(packet_data[38:])
                p.IP_header.get_icmp_src_port(packet_data[62:64])
                if p.IP_header.icmp_type == 11:
                    p.IP_header.get_icmp_seq_num(packet_data[68:70])
                    icmp_packets.append(p)
                if p.IP_header.icmp_type == 8:
                    p.IP_header.get_udp_seq_num(packet_data[40:42])
                    udp_packets.append(p)

            if p.IP_header.protocol == 17:
                p.IP_header.get_udp_src_port(packet_data[34:36])
                udp_packets.append(p)

    intermediate_nodes = []
    pairs = []
    printed = []
    rtts = []
    fragments = []
    node_num = 1
    dst_found = False
    src_node = None
    dest_node = None

    for udp_packet in udp_packets:
        for icmp_packet in icmp_packets:
            if udp_packet.IP_header.ttl == 1 and not dst_found:
                dest_node = udp_packet
                src_node = udp_packet
                dst_found = True
            if icmp_packet.IP_header.ttl == 1 and not dst_found:
                dest_node = icmp_packet
                src_node = icmp_packet
                dst_found = True

            if icmp_packet.IP_header.icmp_type == 11 and udp_packet.IP_header.icmp_type == 8:
                # Windows
                if icmp_packet.IP_header.icmp_seq_num == udp_packet.IP_header.udp_seq_num:
                    pairs.append([udp_packet, icmp_packet,
                                  udp_packet.IP_header.ttl])
            if icmp_packet.IP_header.icmp_src_port == udp_packet.IP_header.udp_src_port:
                pairs.append([udp_packet, icmp_packet,
                             udp_packet.IP_header.ttl])

        if udp_packet.IP_header.flags["MF"] == True:
            found = False
            for fragment in fragments:
                if fragment["id"] == udp_packet.IP_header.identification:
                    found = True
                    fragment["num_frags"] += 1
            if not found:
                fragments.append({
                    "id": udp_packet.IP_header.identification,
                    "num_frags": 1
                })
        else:
            for fragment in fragments:
                if fragment["id"] == udp_packet.IP_header.identification:
                    found = True
                    fragment["num_frags"] += 1
                    fragment["offset"] = udp_packet.IP_header.fragment_offset

    for pair in pairs:
        if pair[1].IP_header.src_ip not in intermediate_nodes and pair[1].IP_header.src_ip != dest_node.IP_header.dst_ip:
            intermediate_nodes.append(pair[1])

    print("The IP address of the source node: ", src_node.IP_header.src_ip)
    print("The IP address of the ultimate destination node: ",
          dest_node.IP_header.dst_ip)
    print("The IP adresses of the intermediate destination nodes: ")
    for node in intermediate_nodes:
        if node.IP_header.src_ip not in printed:
            print("\trouter " + str(node_num) + ": " + node.IP_header.src_ip)
            printed.append(node.IP_header.src_ip)
            node_num += 1

    printed = []
    print("\nThe values in the protocol field of IP headers: ")
    if len(icmp_packets) > 0:
        print("\t1: ICMP")
    if len(udp_packets) > 0:
        print("\t17: UDP")
    print()
    # TODO:
    # - ACCOUNT FOR WINDOWS TRACES

    for fragment in fragments:
        print("The number of fragments created from the original datagram with id " +
              str(fragment["id"]) + " is: " + str(fragment["num_frags"]))
        print("The offset of the last fragment is: " + str(fragment["offset"]))
        print()

    for node in intermediate_nodes:
        total_time = 0
        values = []
        stddev = 0.0

        rtts = [pair for pair in pairs if pair[1].IP_header.src_ip ==
                node.IP_header.src_ip]
        for rtt in rtts:
            total_time += (rtt[1].timestamp - rtt[0].timestamp)
            values.append(rtt[1].timestamp * 1000 - rtt[0].timestamp * 1000)
        if len(rtts) > 0 and rtt[1].IP_header.src_ip not in printed:
            if len(values) > 2:
                stddev = statistics.stdev(values)
            print("The avg RTT between " + rtt[0].IP_header.src_ip +
                  " and " + rtt[1].IP_header.src_ip + " is: " + str(round((total_time * 1000 / len(rtts)), 6)) + " ms, the s.d. is: " + str(round(stddev, 6)) + " ms")
            printed.append(rtt[1].IP_header.src_ip)

    values = []
    stddev = 0.0
    total_time = 0
    rtts = [pair for pair in pairs if pair[1].IP_header.src_ip ==
            dest_node.IP_header.dst_ip]
    for rtt in rtts:
        total_time += rtt[1].timestamp - rtt[0].timestamp
        values.append((rtt[1].timestamp * 1000) - (rtt[0].timestamp * 1000))
    if len(rtts) > 0 and rtt[1].IP_header.src_ip not in printed:
        if len(values) > 2:
            stddev = statistics.stdev(values)
        print("The avg RTT between " + src_node.IP_header.dst_ip +
              " and " + rtt[1].IP_header.src_ip + " is: " + str(round((total_time / len(rtts)) * 1000, 6)) + " ms, the s.d. is: " + str(round(stddev, 6)) + " ms")
        printed.append(rtt[1].IP_header.src_ip)
