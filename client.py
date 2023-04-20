import hashlib
from socket import *
import struct
import json
import time
from os.path import join, getsize
import argparse

# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', action='store', required=False, dest="server_ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("--id", default='2036327', action='store', required=False, dest="id",
                       help="your ID")
    parse.add_argument("--f", default='', action='store', required=False, dest="file",
                       help="File path. Default is empty(no file will be upload).")
    return parse.parse_args()


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data

def make_require_packet_login(operation, status_code, data_type, status_msg, json_data, id,bin_data=None):
    """
    Make a packet for require
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
    :param status_code: 200 or 400+
    :param data_type: [FILE, DATA, AUTH]
    :param status_msg: A human-readable status massage
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
    json_data[FIELD_TYPE] = data_type
    json_data[FIELD_USERNAME] = id
    json_data[FIELD_PASSWORD] = hashlib.md5(id.encode()).hexdigest()
    return make_packet(json_data, bin_data)

def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data

def make_require_packet_Get(operation, status_code, data_type, status_msg, json_data,key, token,bin_data=None):
    """
    Make a packet for require to send file
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD]
    :param status_code: 200 or 400+
    :param data_type: [FILE, DATA, AUTH]
    :param status_msg: A human-readable status message
    :param key: the file's name
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
    json_data[FIELD_TYPE] = data_type
    json_data[FIELD_KEY]= key
    json_data[FIELD_TOKEN] = token
    return make_packet(json_data, bin_data)

def make_require_packet_upload(operation, status_code, data_type, status_msg, json_data,key,block_index, token,bin_data=None):
    """
    Make a packet for require to send file
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD]
    :param status_code: 200 or 400+
    :param data_type: [FILE, DATA, AUTH]
    :param status_msg: A human-readable status message
    :param key: the file's name
    :param block_index
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
    json_data[FIELD_TYPE] = data_type
    json_data[FIELD_KEY] = key
    json_data[FIELD_BLOCK_INDEX] = block_index
    json_data[FIELD_TOKEN] = token
    return make_packet(json_data, bin_data)

def make_require_packet_Save(operation, status_code, data_type, status_msg, json_data,key,size, token,bin_data=None):
    """
    Make a packet for require to send file
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD]
    :param status_code: 200 or 400+
    :param data_type: [FILE, DATA, AUTH]
    :param status_msg: A human-readable status message
    :param key: the file's name
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
    json_data[FIELD_TYPE] = data_type
    json_data[FIELD_KEY]= key
    json_data[FIELD_SIZE] = size
    json_data[FIELD_TOKEN] = token
    return make_packet(json_data, bin_data)


def get_file_md5(filename):
    """
    Get MD5 value for big file
    :param filename:
    :return:
    """
    m = hashlib.md5()
    with open(filename, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()


def main():
    parser = _argparse()
    server_ip = parser.server_ip
    server_port = parser.port
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((server_ip, int(server_port)))

    id = parser.id
    packet1 = make_require_packet_login(OP_LOGIN, {}, TYPE_AUTH, "server is ready", {}, id, None)
    clientSocket.send(packet1)
    json_data,bin_data = get_tcp_packet(clientSocket)
    # print token and show it log in successfully
    print(json_data[FIELD_TOKEN])
    print(json_data[FIELD_STATUS_MSG])


    print('ask for another require')

    print('please input the file you want to upload')
    # get upload plan
    key = parser.file
    size =getsize(key)
    packet2 = make_require_packet_Save(OP_SAVE, {}, TYPE_FILE, 'Save A FILE', {}, key,size,json_data[FIELD_TOKEN],None)
    clientSocket.send(packet2)
    # print('have send packet2')
    json_data2,bin_data2 = get_tcp_packet(clientSocket)
    print('get response')
    for keys, values in json_data2.items():
        print(keys + ": " + str(values))
    # print(json_data2[FIELD_STATUS_MSG],json_data2[FIELD_BLOCK_SIZE],json_data2[FIELD_TOTAL_BLOCK],json_data2[FIELD_SIZE])


    print('next step')

    file_path =json_data2[FIELD_KEY]
    block_size = json_data2[FIELD_BLOCK_SIZE]
    file_size = json_data2[FIELD_SIZE]

    with open(file_path, 'rb') as fid:
        for block_index in range(json_data2[FIELD_TOTAL_BLOCK]):
            fid.seek(block_size * block_index)
            if block_size * (block_index + 1) < file_size:
                bin_data = fid.read(block_size)
                packet3 = make_require_packet_upload(OP_UPLOAD,{},TYPE_FILE,"sent a packet",{},key,block_index,json_data[FIELD_TOKEN],bin_data)
                clientSocket.send(packet3)
                json_data3, bin_data3 = get_tcp_packet(clientSocket)
                print(json_data3[FIELD_STATUS_MSG])
            else:
                bin_data = fid.read(file_size - block_size * block_index)
                packet3 = make_require_packet_upload(OP_UPLOAD, {}, TYPE_FILE, "sent a packet", {}, key, block_index,
                                                     json_data[FIELD_TOKEN], bin_data)
                clientSocket.send(packet3)
                json_data3, bin_data3 = get_tcp_packet(clientSocket)
                print(json_data3[FIELD_STATUS_MSG])


    if json_data3[FIELD_MD5] == get_file_md5(key):
        print("file is received by the server properly")
    else:
        print("file is not received by the server properly")



if __name__ == '__main__':
    main()