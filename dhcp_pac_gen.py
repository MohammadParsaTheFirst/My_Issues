import random
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Dot3, Ether
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.all import Raw
from scapy.sendrecv import sniff, sendp
from functools import reduce


SERVER_NAME_NOT_GIVEN = Raw(load=bytes([0]*64))
FILENAME_NOT_GIVEN = Raw(load=bytes([0]*128))


def gen_random_mac():
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

def gen_random_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))
# -----------------------------------------------------------------------------------------
# DHCP message types:
_DHCP_TYPE = {  # of dhcp payload
    "DHCP_DISCOVER":                 1,# on it
    "DHCP_OFFER":                    2,# on it
    "DHCP_REQUEST":                  3,# on it
    "DHCP_DECLINE":                  4,# on it
    "DHCP_ACK":                      5,# on it
    "DHCP_NAK":                      6,# on it
    "DHCP_RELEASE":                  7,
    "DHCP_INFORM":                   8,
    "DHCP_FORCE_RENEW":              9,# on it
    "DHCP_LEASE_QUERY":              10,
    "DHCP_LEASE_UNASSIGNED":         11,
    "DHCP_LEASE_UNKNOWN":            12,
    "DHCP_LEASE_ACTIVE":             13,
    "DHCP_BULK_LEASE_QUERY":         14,
    "DHCP_LEASE_QUERY_DONE":         15,
    "DHCP_ACTIVE_LEASE_QUERY":       16,
    "DHCP_LEASE_QUERY_STATUS":       17,
    "DHCP_TLS":                      18,
}

_DHCP_OPTIONS = { # the code of dhcp options
    "Subnet_Mask": Raw(load=b'\x01'),              # option 1
    "Router": Raw(load=b'\x03'),                   # option 3
    "Domain_Name_Server": Raw(load=b'\x06'),       # option 6
    "Domain_Name": Raw(load=b'\x0f'),              # option 15
    "Broadcast_Address": Raw(load=b'\x1c'),        # option 28
    "Requested_IP_Address": Raw(load=b'\x32'),     # option 50
    "IP_Address_Lease_Time": Raw(load=b'\x33'),    # option 51
    "DHCP_Message_Type": Raw(load=b'\x35'),        # option 53
    "Server_Identifier": Raw(load=b'\x36'),        # option 54
    "Param_Request_List" : Raw(load=b'\x37'),      # option 55
    "Message": Raw(load=b'\x38'),                  # option 56
    "Max_DHCP_Message_Size": Raw(load=b'\x39'),    # option 57
    "Renewal_Time_Value": Raw(load=b'\x3a'),       # option 58
    "Rebinding_Time_Value": Raw(load=b'\x3b'),     # option 59
    "Vendor_Class_Identifier": Raw(load=b'\x3c'),  # option 60
    "Client_Identifier": Raw(load=b'\x3d'),        # option 61
    "END": Raw(load=b'\xff'),                      # option 255
}

_DHCP_OPTIONS_LEN = { # length of options
    "Subnet_Mask": Raw(load=b'\x04'),            # option 1  --- 4 bytes
    "Requested_IP_Address": Raw(load=b'\x04'),   # option 50 --- 4 bytes
    "IP_Address_Lease_Time": Raw(load=b'\x04'),  # option 51
    "DHCP_Message_Type": Raw(load=b'\x01'),      # option 53 --- 1 byte
    "Server_Identifier": Raw(load=b'\x04'),      # option 54 --- 4 bytes
    "Param_Request_List": Raw(load=b'\x04'),     # option 55 --- 4 bytes (can be optional)
    "Renewal_Time_Value": Raw(load=b'\x04'),     # option 58
    "Rebinding_Time_Value": Raw(load=b'\x3b'),   # option 59 --- 4 bytes
    "Client_Identifier": Raw(load=b'\x07'),      # option 61 --- 7 bytes
}

_PARAM_REQ_LIST = { # param_request_lists options
    "subnet-mask": Raw(load=b'\x01'),       # 1
    "router": Raw(load=b'\x03'),            # 3
    "dns": Raw(load=b'\x06'),               # 6
    "host-name": Raw(load=b'\x0c'),         # 12
    "domain-name": Raw(load=b'\x0f'),       # 15
    "broadcast-addr": Raw(load=b'\x1c'),    # 28
    "ntp-servers": Raw(load=b'\x2a'),       # 42
    "requested-ip": Raw(load=b'\x32'),      # 50
    "lease-time": Raw(load=b'\x33'),        # 51
    "dhcp-msg-type": Raw(load=b'\x35'),     # 53
    "server-id": Raw(load=b'\x36'),         # 54
    "param-req-list": Raw(load=b'\x37'),    # 55
    "max-dhcp-msg-size": Raw(load=b'\x39'), # 57
    "renewal-time": Raw(load=b'\x3a'),      # 58
    "rebinding-time": Raw(load=b'\x3b'),    # 59
    "vendor-class-id": Raw(load=b'\x3c'),   # 60
    "client-id": Raw(load=b'\x3d'),         # 61
}


class MYDHCP:
    def __init__(self, dhcp_type, OF_DHCP, OF_ETH):
        self.msg_type = self.set_msg_type(dhcp_type)                                  # message type (request/reply)
        self.HW_TYPE = Raw(load=b'\x01')                                              # Hardware Type (Ethernet 10M)
        self.HW_len = Raw(load=b'\x06')                                               # 6
        self.HOPS = Raw(load=b'\x00')
        self.x_id = Raw(load=b'\x86\x59\x86\x59')                                     # transaction id
        self.seconds = Raw(load=b'\x00\x00')                                          # elapsed time
        self.flags = Raw(load=b'\x80\x00')                                            # broadcast flag
        self.ciaddr = Raw(load=OF_DHCP[0])                                            # client ip address
        self.yiaddr = Raw(load=OF_DHCP[1])                                            # your ip address
        self.siaddr = Raw(load=OF_DHCP[2])                                            # server ip address
        self.giaddr = Raw(load=OF_DHCP[3])                                            # gateway ip address
        self.chaddr = Raw(load=OF_DHCP[4])                                            # client hardware address (mac)
        self.chaddr_pad = Raw(load=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')       # client hardware address padding
        self.sname = OF_DHCP[5]                                                       # server host name (DHCP server)
        self.file_name = OF_DHCP[6]                                                   # boot file name
        self.magic_cookie = Raw(load=b'\x63\x82\x53\x63')                             # magic cookie
        self.dhcp_server_ip = Raw(load=b'\x04\x02\x02\x04')                           # dhcp server ip
        self.subnet_mask = Raw(load=b'\xff\xff\x00\x00')                              # subnet mask
        self.OP = bytes([_DHCP_TYPE[dhcp_type]])                                      # DHCP message type (in option layer)
        self.__DHCP_OPTIONS__ = {
            "DHCP_DISCOVER": [ # 1
                _DHCP_OPTIONS["Param_Request_List"] / _DHCP_OPTIONS_LEN["Param_Request_List"] /
                _PARAM_REQ_LIST["subnet-mask"] / _PARAM_REQ_LIST["router"] / _PARAM_REQ_LIST["dns"] / _PARAM_REQ_LIST["ntp-servers"],
                _DHCP_OPTIONS["Client_Identifier"] / _DHCP_OPTIONS_LEN["Client_Identifier"] / self.HW_TYPE / Raw(load=OF_ETH[1]),
                _DHCP_OPTIONS["Requested_IP_Address"] / _DHCP_OPTIONS_LEN["Requested_IP_Address"] / self.ciaddr,
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["END"]
            ],
            "DHCP_OFFER": [ # 2
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["Renewal_Time_Value"] / _DHCP_OPTIONS_LEN["Renewal_Time_Value"] / Raw(load=b'\x00\x00\x07\x08'),
                _DHCP_OPTIONS["Rebinding_Time_Value"] / _DHCP_OPTIONS_LEN["Rebinding_Time_Value"] / Raw(load=b'\x00\x00\x0c\x4e'),
                _DHCP_OPTIONS["IP_Address_Lease_Time"] / _DHCP_OPTIONS_LEN["IP_Address_Lease_Time"] / Raw(load=b'\x00\x00\x0e\x10'),
                _DHCP_OPTIONS["END"]
            ],
            "DHCP_REQUEST": [ # 3
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["Client_Identifier"] / _DHCP_OPTIONS_LEN["Client_Identifier"] / self.HW_TYPE / Raw(load=OF_ETH[1]),
                _DHCP_OPTIONS["Requested_IP_Address"] / _DHCP_OPTIONS_LEN["Requested_IP_Address"] / self.ciaddr,
                _DHCP_OPTIONS["Param_Request_List"] / _DHCP_OPTIONS_LEN["Param_Request_List"] /
                _PARAM_REQ_LIST["subnet-mask"] / _PARAM_REQ_LIST["router"] / _PARAM_REQ_LIST["dns"] / _PARAM_REQ_LIST["ntp-servers"],
                _DHCP_OPTIONS["Server_Identifier"] / _DHCP_OPTIONS_LEN["Server_Identifier"] / self.dhcp_server_ip,
                _DHCP_OPTIONS["END"] #_DHCP_OPTIONS["Message"]   ---> to add a message in here
            ],
            "DHCP_DECLINE": [ # 4
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["Server_Identifier"] / _DHCP_OPTIONS_LEN["Server_Identifier"] / self.dhcp_server_ip,
                _DHCP_OPTIONS["Requested_IP_Address"] / _DHCP_OPTIONS_LEN["Requested_IP_Address"] / self.ciaddr,
                _DHCP_OPTIONS["END"]
            ],
            "DHCP_ACK": [ # 5
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["Renewal_Time_Value"] / _DHCP_OPTIONS_LEN["Renewal_Time_Value"] / Raw(load=b'\x00\x00\x07\x08'),
                _DHCP_OPTIONS["Rebinding_Time_Value"] / _DHCP_OPTIONS_LEN["Rebinding_Time_Value"] / Raw(load=b'\x00\x00\x0c\x4e'),
                _DHCP_OPTIONS["IP_Address_Lease_Time"] / _DHCP_OPTIONS_LEN["IP_Address_Lease_Time"] / Raw(load=b'\x00\x00\x0e\x10'),
                _DHCP_OPTIONS["Server_Identifier"] / _DHCP_OPTIONS_LEN["Server_Identifier"] / self.dhcp_server_ip,
                _DHCP_OPTIONS["Subnet_Mask"] / _DHCP_OPTIONS_LEN["Subnet_Mask"] / self.subnet_mask,
                _DHCP_OPTIONS["END"]
            ],
            "DHCP_NAK": [ # 6
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["Client_Identifier"] / _DHCP_OPTIONS_LEN["Client_Identifier"] / self.HW_TYPE / Raw(load=OF_ETH[1]),
                _DHCP_OPTIONS["Requested_IP_Address"] / _DHCP_OPTIONS_LEN["Requested_IP_Address"] / self.ciaddr,
                _DHCP_OPTIONS["Server_Identifier"] / _DHCP_OPTIONS_LEN["Server_Identifier"] / self.dhcp_server_ip,
                _DHCP_OPTIONS["Subnet_Mask"] / _DHCP_OPTIONS_LEN["Subnet_Mask"] / self.subnet_mask,
                _DHCP_OPTIONS["END"]
            ],
            "DHCP_FORCE_RENEW": [ # 9
                _DHCP_OPTIONS["DHCP_Message_Type"] / _DHCP_OPTIONS_LEN["DHCP_Message_Type"] / self.OP,
                _DHCP_OPTIONS["END"]
            ]
        }  # what ip address for dhcp nak

    def get_main_dhcp(self):
        return self.msg_type / self.HW_TYPE / self.HW_len / self.HOPS / self.x_id / self.seconds / \
                    self.flags / self.ciaddr / self.yiaddr / self.siaddr / self.giaddr / self.chaddr / \
                    self.chaddr_pad / self.sname / self.file_name / self.magic_cookie

    def get_packet(self, dhcp_type):
        if dhcp_type not in self.__DHCP_OPTIONS__:
            raise ValueError(f"Unknown DHCP type: {dhcp_type}")
        elif dhcp_type not in _DHCP_TYPE:
            raise NotImplementedError
        random.shuffle(self.__DHCP_OPTIONS__[dhcp_type])
        options = [self.get_main_dhcp()] + self.__DHCP_OPTIONS__[dhcp_type]
        return reduce(lambda x, y: x / y, options)

        #random.shuffle(self.__DHCP_OPTIONS__[dhcp_type])
        #return self.get_main_dhcp() / self.__DHCP_OPTIONS__[dhcp_type]

    MESSAGE_TYPE = {
        "BOOT_REQUEST": Raw(load=b'\x01'),
        "BOOT_REPLY": Raw(load=b'\x02')
    }

    def set_msg_type(self, dhcp_type):
        if dhcp_type == "DHCP_DISCOVER":              # 1
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_OFFER":               # 2
            return self.MESSAGE_TYPE["BOOT_REPLY"]
        elif dhcp_type == "DHCP_REQUEST":             # 3
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_DECLINE":             # 4
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_ACK":                 # 5
            return self.MESSAGE_TYPE["BOOT_REPLY"]
        elif dhcp_type == "DHCP_NAK":                 # 6
            return self.MESSAGE_TYPE["BOOT_REPLY"]
        elif dhcp_type == "DHCP_RELEASE":             # 7
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_INFORM":              # 8
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_FORCE_RENEW":         # 9
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_LEASE_QUERY":         # 10
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_LEASE_UNASSIGNED":    # 11
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_LEASE_UNKNOWN":       # 12
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_LEASE_ACTIVE":        # 13
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_BULK_LEASE_QUERY":    # 14
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_LEASE_QUERY_DONE":    # 15
            return self.MESSAGE_TYPE["BOOT_REPLY"]
        elif dhcp_type == "DHCP_ACTIVE_LEASE_QUERY":  # 16
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type == "DHCP_LEASE_QUERY_STATUS":  # 17
            return self.MESSAGE_TYPE["BOOT_REPLY"]
        elif dhcp_type == "DHCP_TLS":                 # 18
            return self.MESSAGE_TYPE["BOOT_REQUEST"]
        elif dhcp_type not in _DHCP_TYPE:
            return NotImplementedError
        else:
            raise ValueError(f"Unknown DHCP type: {dhcp_type}")




eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=gen_random_mac())
ip = IP(src="0.0.0.0", dst="255.255.255.255")#--------------------
udp = UDP(sport=68, dport=67)#-------------------------------

dhcp = DHCP(options=[
    ("message-type", "discover"),
    ("client_id", b"\x01\x00\x0c\x29\x63\x1d\xbd"),
    ("hostname", "client-hostname"),
    ("param_req_list", [1, 3, 6, 15, 28, 51, 58, 59]),
    ("vendor_class_id", "MSFT 5.0"),
    ("requested_addr", "192.168.1.100"),
    ("lease_time", 43200),  # 12 hours
    ("renewal_time", 21600),  # 6 hours
    ("rebinding_time", 37800),  # 10.5 hours
    "end"
])

client_mac = Raw(load=b'\x01\x02\x03\x04\x05\x06')

of_eth =[
    Raw(load=b'\xff\xff\xff\xff\xff\xff'),
    client_mac
]
of_dhcp = [
        b'\x11\x11\x11\x11',            # client_ip = 0.0.0.0
        b'\x22\x22\x22\x22',            # your_ip = 0.0.0.0
        b'\x33\x33\x33\x33',            # server_ip = 0.0.0.0
        b'\x44\x44\x44\x44',            # gateway_ip = 0.0.0.0
        client_mac,                     # client mac
        SERVER_NAME_NOT_GIVEN,          # server name
        FILENAME_NOT_GIVEN              #
    ]

ddhcp = MYDHCP("DHCP_DISCOVER",of_dhcp, of_eth).get_packet("DHCP_DISCOVER")

packet = eth / ip / udp / ddhcp
#sendp(packet, iface="enx00e04c680cd5", loop=1, verbose=1)
sendp(packet, iface="lo", loop=1, verbose=1)


""" 
This module successfully generated DHCP traffic.
it seemed that applying permutations in OptionHeader in DHCP 
did not wreak havoc on DHCP functioning. 
"""
