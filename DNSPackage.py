import socket
import binascii
try:
    import bitstring
except ImportError:
    raise ImportError("Bitstring library wasn't found")

QTYPE = {1: "A", 2: "NS", 5: 'CNAME', 6:'SOA', 12: 'PTR', 15: "MX", 28: "AAAA"}
QR_TYPE = {0: 'query', 1: 'response'}
OPCODE = {0: 'standard', 1: 'inverse', 2: 'status_server'}
AUTHORITY = {0: 'not authority', 1: 'authority'}
TRUNCATED = {0: 'not truncated', 1: 'truncated'}
RECURSION_DESIRED = {0: 'not desired', 1: 'recursive desired'}
RECURSION_AVAILABLE = {0: 'not available', 1: 'available'}
RCODE = {0: 'no error', 1: 'format error',
         2: 'server failure', 3: 'name error',
         4: 'not implemented', 5: 'refused'}


class DNSError:
    pass


class DNSPackage:
    def __init__(self, header, queries, answer_rr, auth_rr, add_rr):
        self.header = header
        self.queries = queries
        self.answers_rr = answer_rr
        self.auth_rr = auth_rr
        self.add_rr = add_rr

    @staticmethod
    def parse(package):
        try:
            header = DNSHeader.parse(package)
            queries = []
            answers_rr = []
            auth_rr = []
            add_rr = []
            offset = 96  # 96 - header length
            for _ in range(0, header.qdcount):
                query, offset = DNSQuery.parse(package, offset)
                queries.append(query)
            for _ in range(0, header.ancount):
                answer, offset = DNSResponse.parse(package, offset)
                answers_rr.append(answer)
            for _ in range(0, header.nscount):
                answer, offset = DNSResponse.parse(package, offset)
                auth_rr.append(answer)
            for _ in range(0, header.arcount):
                answer, offset = DNSResponse.parse(package, offset)
                add_rr.append(answer)
            return DNSPackage(header, queries, answers_rr, auth_rr, add_rr)
        except BaseException:
            raise DNSError

    def __str__(self):
        """Переопределение метода вывода"""
        result = 'DNS packet:\n'
        result += f'  Header:\n{self.header}'
        if self.queries is not None:
            for query in self.queries:
                result += f'  Query:\n{query}'
        if self.answers_rr is not None:
            for answer in self.answers_rr:
                result += f'  Answer:\n{answer}'
        if self.auth_rr is not None:
            for auth in self.auth_rr:
                result += f'  Authoritative nameserver:\n{auth}'
        if self.add_rr is not None:
            for add in self.add_rr:
                result += f'  Additional record:\n{add}'
        return result

    def to_bytes(self):
        """Перевод DNS пакета в последоваетльность байт"""
        result = self.header.to_bytes()
        if self.queries is not None:
            for query in self.queries:
                result += query.to_bytes()
        if self.answers_rr is not None:
            for answer in self.answers_rr:
                result += answer.to_bytes()
        if self.auth_rr is not None:
            for auth in self.auth_rr:
                result += auth.to_bytes()
        if self.add_rr is not None:
            for add in self.add_rr:
                result += add.to_bytes()
        return result


class DNSHeader:
    def __init__(self, transaction_id, qtype, opcode, authority, truncated,
                 recursion_desired, recursion_available, rcode,
                 query, response, authority_response, additional_response):
        self.trans_id = transaction_id
        self.qtype = qtype
        self.opcode = opcode
        self.auth = authority
        self.trunc = truncated
        self.rec_des = recursion_desired
        self.rec_av = recursion_available
        self.rcode = rcode
        self.qdcount = query
        self.ancount = response
        self.nscount = authority_response
        self.arcount = additional_response

    @staticmethod
    def parse(header_part):
        trans_id = bitstring.Bits(header_part)[0:16].uint
        qtype = bitstring.Bits(header_part)[16:17].uint
        opcode = bitstring.Bits(header_part)[17:21].uint
        auth = bitstring.Bits(header_part)[21:22].uint
        trunc = bitstring.Bits(header_part)[22:23].uint
        rec_des = bitstring.Bits(header_part)[23:24].uint
        rec_av = bitstring.Bits(header_part)[24:25].uint
        rcode = bitstring.Bits(header_part)[28:32].uint
        query = bitstring.Bits(header_part)[32:48].uint
        resp = bitstring.Bits(header_part)[48:64].uint
        auth_resp = bitstring.Bits(header_part)[64:80].uint
        add_resp = bitstring.Bits(header_part)[80:96].uint
        return DNSHeader(trans_id, qtype, opcode, auth,
                         trunc, rec_des, rec_av, rcode,
                         query, resp, auth_resp, add_resp)

    def to_bytes(self):
        """Перевод заголовка в последовательность байт"""
        bits_packet = bitstring.BitArray(length=96)
        bits_packet[0:16] = bitstring.pack('uint: 16', self.trans_id)
        bits_packet[16:17] = bitstring.pack('uint: 1', self.qtype)
        bits_packet[17:21] = bitstring.pack('uint: 4', self.opcode)
        bits_packet[21:22] = bitstring.pack('uint: 1', self.auth)
        bits_packet[22:23] = bitstring.pack('uint: 1', self.trunc)
        bits_packet[23:24] = bitstring.pack('uint: 1', self.rec_des)
        bits_packet[24:25] = bitstring.pack('uint: 1', self.rec_av)
        bits_packet[28:32] = bitstring.pack('uint: 4', self.rcode)
        bits_packet[32:48] = bitstring.pack('uint: 16', self.qdcount)
        bits_packet[48:64] = bitstring.pack('uint: 16', self.ancount)
        bits_packet[64:80] = bitstring.pack('uint: 16', self.nscount)
        bits_packet[80:96] = bitstring.pack('uint: 16', self.arcount)
        return bits_packet.tobytes()

    def __str__(self):
        result = f'    Transactions ID: {self.trans_id}\n' \
                 f'    Response: Massage is a {QR_TYPE.get(self.qtype)} ({self.qtype})\n' \
                 f'    Opcode: {OPCODE.get(self.opcode, "Reserved value")} ({self.opcode})\n'
        if self.qtype == 0:
            result += f'    Truncated: Massage is {TRUNCATED.get(self.trunc)} ({self.trunc})\n' \
                      f'    Recursion desired: {RECURSION_DESIRED[self.rec_des]} ' \
                      f'({self.rec_des})\n'
        else:
            result += f'    Authoritative: Server is {AUTHORITY.get(self.auth)} for domain ' \
                      f'({self.auth})\n' \
                      f'    Truncated: Massage is {TRUNCATED.get(self.trunc)} ({self.trunc})\n' \
                      f'    Recursion desired: {RECURSION_DESIRED[self.rec_des]} ' \
                      f'({self.rec_des})\n' \
                      f'    Recursion available: Server {RECURSION_AVAILABLE[self.rec_av]} ' \
                      f'({self.rec_av})\n' \
                      f'    Reply code: {RCODE.get(self.rcode, "Reserved value")} ({self.rcode})\n'
        result += f'    Question: {self.qdcount}\n' \
                  f'    Answer RRs: {self.ancount}\n' \
                  f'    Authority RRs: {self.nscount}\n' \
                  f'    Additional RRs: {self.arcount}\n'
        return result


class DNSQuery:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    @staticmethod
    def parse(package, offset):
        qname, offset = parse_name(package, offset, '')
        qtype = bitstring.Bits(package)[offset: offset + 16].uint
        offset += 16
        qclass = bitstring.Bits(package)[offset: offset + 16].uint
        offset += 16
        return DNSQuery(qname, qtype, qclass), offset

    def __str__(self):
        """Переопределение метода вывода"""
        return f'    Name: {self.qname}\n' \
               f'    Type: {QTYPE.get(self.qtype, "Unknown")} ({self.qtype})\n' \
               f'    Class: IN ({self.qclass})\n'

    def to_bytes(self):
        """Перевод запроса в последовательность байт"""
        bytes_name = _name_to_bytes(self.qname)
        bits_packet = bitstring.BitArray(length=32)
        bits_packet[0:16] = bitstring.pack('uint: 16', self.qtype)
        bits_packet[16:32] = bitstring.pack('uint: 16', self.qclass)
        return bytes_name + bits_packet.tobytes()


class DNSResponse:
    def __init__(self, name, r_type, r_class,
                 ttl, rdlength, rdata):
        self.name = name
        self.r_type = r_type
        self.r_class = r_class
        self.ttl = ttl
        self.rdlentgth = rdlength
        self.rdata = rdata

    @staticmethod
    def parse(package, offset):
        name, offset = parse_name(package, offset, '')
        r_type = bitstring.Bits(package)[offset: offset + 16].uint
        offset += 16
        r_class = bitstring.Bits(package)[offset: offset + 16].uint
        offset += 16
        ttl = bitstring.Bits(package)[offset: offset + 32].uint
        offset += 32
        rdlength = bitstring.Bits(package)[offset: offset + 16].uint
        offset += 16
        rdata, offset = parse_address(package, offset, r_type, rdlength)

        return DNSResponse(name, r_type, r_class, ttl, rdlength, rdata), offset

    def to_bytes(self):
        bytes_name = _name_to_bytes(self.name)
        bits_packet = bitstring.BitArray()
        bits_packet[0:16] = bitstring.pack('uint: 16', self.r_type)
        bits_packet[16:32] = bitstring.pack('uint: 16', self.r_class)
        bits_packet[32:64] = bitstring.pack('uint: 32', self.ttl)
        if self.r_type == 1:
            rdata = _address_to_bytes(self.rdata)
            bits_packet[64:80] = bitstring.pack('uint: 16', self.rdlentgth)
        elif self.r_type == 28:
            rdata = ipv6_to_bytes(self.rdata)
            bits_packet[64:80] = bitstring.pack('uint: 16', self.rdlentgth)
        else:
            rdata = _name_to_bytes(self.rdata)
            bits_packet[64:80] = bitstring.pack('uint: 16', len(rdata))

        return bytes_name + bits_packet.tobytes() + rdata


class DNSAuthority:
    def __init__(self, name, r_type, r_class, ttl,
                 date_length, prime_ns, resp_auth, ser_num,
                 refresh_inter, retry_int, expire_limit, min_ttl,):
        self.name = name
        self.r_type = r_type
        self.r_class = r_class
        self.ttl = ttl
        self.date_length = date_length
        self.prime_ns = prime_ns
        self.resp_auth = resp_auth
        self.ser_num = ser_num
        self.refresh_interval = refresh_inter
        self.retry_interval = retry_int
        self.expire_limit = expire_limit
        self.min_ttl = min_ttl

    @staticmethod
    def parse(package, offset):
        package_bits = bitstring.Bits(package)
        name, offset = parse_name(package, offset, '')
        r_type = package_bits[offset: offset + 16].uint
        offset += 16
        r_class = package_bits[offset: offset + 16].uint
        offset += 16
        ttl = package_bits[offset: offset + 32].uint
        offset += 32
        date_length = package_bits[offset: offset + 16].uint
        offset += 16
        prime_name_server, offset = parse_name(package, offset, '')
        resp_auth, offset = parse_name(package, offset, '')
        serial_number = package_bits[offset: offset + 32].uint
        offset += 32
        refresh_interval = package_bits[offset: offset + 32].uint
        offset += 32
        retry_interval = package_bits[offset: offset + 32].uint
        offset += 32
        expire_limit = package_bits[offset: offset + 32].uint
        offset += 32
        minimum_ttl = package_bits[offset: offset + 32].uint
        offset += 32
        return DNSAuthority(name, r_type, r_class, ttl, date_length, prime_name_server, resp_auth,
                            serial_number, refresh_interval, retry_interval, expire_limit,
                            minimum_ttl), offset

    def to_bytes(self):
        name = _name_to_bytes(self.name)
        bits_packets = bitstring.BitArray()
        bits_packets[0: 16] = bitstring.pack('uint: 16', self.r_type)
        bits_packets[16: 32] = bitstring.pack('uint: 16', self.r_class)
        bits_packets[32: 64] = bitstring.pack('uint: 32', self.ttl)
        bits_packets[64: 80] = bitstring.pack('uint: 16', self.date_length)
        prime_ns = _name_to_bytes(self.prime_ns)
        auth_ns = _name_to_bytes(self.resp_auth)
        serial = bitstring.pack('uint: 32', self.ser_num)
        refresh_int = bitstring.pack('uint: 32', self.refresh_interval)
        retry_int = bitstring.pack('uint: 32', self.retry_interval)
        expire_limit = bitstring.pack('uint: 32', self.expire_limit)
        min_ttl = bitstring.pack('uint: 32', self.min_ttl)
        return (name + bits_packets.tobytes() + prime_ns + auth_ns + serial +
               refresh_int + retry_int + expire_limit + min_ttl).tobytes()


# def rdata_to_bytes(name, queries_offsets):
#     prefix = ''
#     for query in queries_offsets.keys():
#         suffix_start = name.query.rfind(query)
#         if name.query.rfind(query) != -1:
#             prefix = _name_to_bytes(name[:suffix_start - 1])
#             suffix = bitstring.pack('uint: 16', 192 + queries_offsets[query] // 8).tobytes()
#     return prefix + suffix


def _name_to_bytes(name):
    bits_name = bitstring.BitArray()
    name_parts_array = name.split('.')
    name_length = 0
    index = 0
    for name_part in name_parts_array:
        bits_name[index:index + 8] = bitstring.pack('uint: 8', len(name_part))
        name_length += len(name_part) + 1
        index += 8
        for char in name_part:
            bits_name[index:index + 8] = bitstring.pack('hex: 8', char.encode('ASCII').hex())
            index += 8
    bits_name[index: index + 8] = bitstring.pack('uint: 8', 0)
    name_length += 1
    return bits_name.tobytes()


def ipv6_to_bytes(address):
    bits_address = bitstring.BitArray()
    addr_parts = address.split(':')
    index = 0
    for addr_part in addr_parts:
        if addr_part == '':
            break
        addr = int('0x' + addr_part, 16)
        bits_address[index: index + 16] = bitstring.pack('uint: 16', addr)
        index += 16
    for _ in range(0, 6):
        bits_address[index: index + 8] = bitstring.pack('uint: 8', 0)
        index += 8
    last_part = int('0x' + addr_parts[-1], 16)
    bits_address[index: index + 16] = bitstring.pack('uint: 16', last_part)
    return bits_address.tobytes()


def _address_to_bytes(address):
    bits_address = bitstring.BitArray()
    address_parts_array = address.split('.')
    index = 0
    for address_part in address_parts_array:
        address = int(address_part)
        bits_address[index:index + 8] = bitstring.pack('uint: 8', address)
        index += 8
    return bits_address.tobytes()


def parse_name(packet, index, name):
    bit_packet = bitstring.Bits(packet)
    count_of_char = bit_packet[index:index + 8].uint
    while count_of_char != 0:
        if count_of_char >= 192:
            hoop_place = bit_packet[index+2:index+16].uint * 8
            name = parse_name(packet, hoop_place, name)[0]
            return name, index + 16
        else:
            index += 8
            for i in range(count_of_char):
                name += bit_packet[index:index+8].bytes.decode('ASCII')
                index += 8
            name += '.'
        count_of_char = bit_packet[index:index+8].uint
    else:
        return name[:-1], index + 8


def parse_address(package, offset, r_type, r_len):
    package_bits = bitstring.BitArray(package)
    address = ''
    if r_type == 1:
        for _ in range(0, r_len):
            address += str(package_bits[offset: offset + 8].uint) + '.'
            offset += 8
        return address[:-1], offset
    elif r_type == 2:
        address, offset = parse_name(package, offset, '')

    elif r_type == 5:
        address, offset = parse_name(package, offset, '')

    elif r_type == 6:
        address, offset = parse_name(package, offset, '')

    elif r_type == 15:
        address, offset = parse_name(package, offset + 16, '')

    elif r_type == 28:
        for _ in range(0, 4):
            address += str(package_bits[offset: offset + 16].hex) + ':'
            offset += 16

        offset += 48
        address += ':' + str(package_bits[offset: offset + 16].hex)
        offset+=16
    return address, offset