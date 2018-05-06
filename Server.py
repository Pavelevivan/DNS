import socket
from DNSPackage import *
from datetime import datetime, timedelta
import logging
import pickle
import os
"""
Задачи: 1: Разобраться с устройством DNS,
        2: Разобраться с устройством пакетов,
        3: Узнать набор команд
"""


logger = logging.getLogger('server')
file_handler = logging.FileHandler("logs.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

CASH_FILE = 'dns_cash.pickle'
DNS_SERVER = 'ns1.e1.ru'
PORT = 53
CASH = dict()  # (name, type, class): (resource record, additional time)
ADDRESSES = {}


def clear_outdated():
    for key, records in CASH.items():
        CASH[key] = [(record, add_time) for record, add_time in records if is_record_outdated(record, add_time)]


def is_record_outdated(record, add_time):
    return datetime.now() - add_time <= timedelta(seconds=record.ttl)


def extract_all_records(packet):
    useful_rec = packet.auth_rr + packet.answers_rr + packet.add_rr
    for r_rec in useful_rec:
        if r_rec.r_type in QTYPE:
            add_record(r_rec)
            logger.info('Added record: key{}{}'.format((r_rec.name, r_rec.r_type, r_rec.r_class), r_rec))


def add_record(r_rec):
    key = (r_rec.name, r_rec.r_type, r_rec.r_class)
    if key not in CASH.keys():
        CASH[key] = [(r_rec, datetime.now())]
    else:
        CASH[key].append((r_rec, datetime.now()))
    logger.info("Added in cash {}".format(r_rec))


def make_standard_header(transactions_id, quest_len, answer_len, auth_len, add_len):
    return DNSHeader(transactions_id, 1, 0, 0, 0, 1, 0, 0, quest_len, answer_len, auth_len, add_len)


def send(sock, message, addr, port):
    try:
        sock.sendto(message, (addr, port))
        logger.info("Message sent {}".format(message))
    except OSError:
        logger.info("Failed to send response {} {}".format(addr, message))


def get_response(packet):
    cash = CASH
    clear_outdated()
    answers = []
    if not CASH:
        return []
    for query in packet.queries:
        key = (query.qname, query.qtype, query.qclass)
        if query.qtype in QTYPE:
            if key in CASH.keys():
                for record in CASH[key]:
                    answers.append(record[0])
    if not answers:
        return []
    else:
        header = make_standard_header(packet.header.trans_id, 1, len(answers), 0, 0)
        return DNSPackage(header, packet.queries, answers, [], [])


def get_response_from_server(sock, packet):
    response = None
    try:
        send(sock, packet.to_bytes(), DNS_SERVER, PORT)
        data, address = sock.recvfrom(1024)
        response = DNSPackage.parse(data)
        extract_all_records(response)
    except OSError:
        logger.info("Failed to send request")
    return response


def get_cash_from_memory():
    if not os.path.exists(CASH_FILE):
        f = open(CASH_FILE, 'w').close()
    cash = dict()
    try:
        if os.path.getsize(CASH_FILE) > 0:
            with open(CASH_FILE, "rb") as f:
                cash = pickle.load(f)
                logger.info("Cash loaded {}".format(CASH))
    except OSError:
        logger.info("Loading cash failed")
    return cash


def main():
    global CASH
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", PORT))
    sock.settimeout(2)
    CASH = get_cash_from_memory()
    while True:
        try:
            data = ''
            data, address = sock.recvfrom(1024)
            packet = DNSPackage.parse(data)
            logger.info('Message Received {}'.format(packet))
            if packet.header.qtype == 0:
                for query in packet.queries:
                    print(query)
                    response = get_response(packet)
                    if response:
                        send(sock, response.to_bytes(), *address)
                        print('Response picked from Cash')
                    else:
                        response = get_response_from_server(sock, packet)
                        if response:
                            send(sock, response.to_bytes(), *address)

        except socket.timeout:
            continue
        except ConnectionResetError:
            continue
        except DNSError:
            print('Ошибка парсинга DNS пакета')
            logger.info('Ошибка парсинга DNS пакета: {}'.format(data))

        finally:
            update_cash()


def update_cash():
        try:
            with open(CASH_FILE, "wb") as file:
                pickle.dump(CASH, file)
                logger.info("Cash successfully updated")
        except OSError:
            logger.info("Download cash failed")


if __name__ == '__main__':
    main()
