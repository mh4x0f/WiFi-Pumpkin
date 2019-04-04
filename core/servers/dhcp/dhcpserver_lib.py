import logging
import socket
from dhcplib.packet import DHCPPacket,_FORMAT_CONVERSION_DESERIAL,DHCP_OPTIONS_TYPES
from dhcplib import net, getifaddrslib
import ipaddress as ip
from queue import Queue
log = logging.getLogger(__name__)
from PyQt4.QtCore import QThread,pyqtSignal,SIGNAL,pyqtSlot,QProcess,QObject,SLOT
import struct

class IpAddressClass(object):
    ''' class for generator ipaddress '''
    def __init__(self, range):
        self.range = range
        self.inital_range = ip.ip_address(range.split('/')[0])
        self.end   = int(self.get_lastOctet(range.split('/')[1]))
        self.ipaddres_list = []
        self.createRangeIp(self.end)

    def createRangeIp(self, end):
        while(str(self.inital_range) != self.range.split('/')[1]):
            self.inital_range += 1
            self.ipaddres_list.append(self.inital_range)

    def get_lastOctet(self,ipaddress):
        return ipaddress.split('.')[-1]

    def add_IpAdressNotUse(self, ip):
        self.ipaddres_list.insert(0,ip)

    def __iter__(self):
        return self

    def __next__(self):
        if (len(self.ipaddres_list) > 0):
            return self.ipaddres_list.pop(0)
        return None



class DHCPProtocol(QObject):
    _request = pyqtSignal(object)
    def __init__(self,DHCPConf, pyqtEmit):
        QObject.__init__(self)
        self.dhcp_conf = DHCPConf
        self._request = pyqtEmit
        self.IPADDR = iter(IpAddressClass(self.dhcp_conf['range']))
        self.leases = {}
        self.queue = Queue()
        self.message = []
        self.started = True

    def connection_made(self, transport):
        self.transport = transport

    def get_DHCPServerResponse(self):
        while self.started:
            self.message.append(self.queue.get())

    def tlv_parse(self, raw):
        '''Parse a string of TLV-encoded options.'''
        ret = {}
        while(raw):
            [tag] = struct.unpack('B', bytes([raw[0]]))
            if tag == 0: # padding
                raw = raw[1:]
                continue
            if tag == 255: # end marker
                break
            [length] = struct.unpack('B', bytes([raw[1]]))
            value = raw[2:2 + length]
            raw = raw[2 + length:]
            if tag in ret:
                ret[tag].append(value)
            else:
                ret[tag] = [value]
        return ret

    def datagram_received(self, data, addr):
        self.leases2 = {}
        # [client_mac] = struct.unpack('!28x6s', data[:34])                # Get MAC address
        # self.leases2[client_mac]['options'] = self.tlv_parse(data[240:])
        # print(self.leases2[client_mac]['options'][12][0])

        packet = DHCPPacket(data)
        log.debug('RECV from %s:\n%s\n', addr, packet)
        send = False
        mac = str(packet.get_hardware_address())

        # self.data = self.tlv_parse(data[240:])
        # print(self.data)


        if (mac not in self.leases.keys()):
            self.ip_client = next(self.IPADDR)
            self.leases[mac] = {'mac_addr': mac, 'ip_addr': str(self.ip_client), 'host_name': 'unknown'}
        else:
            self.ip_client = self.leases[mac]['ip_addr']

        if packet.is_dhcp_discover_packet():
            log.debug('DISCOVER')
            packet.transform_to_dhcp_offer_packet()
            #self._request.emit(packet.)
            packet.set_option('yiaddr', self.ip_client)
            packet.set_option('siaddr', self.dhcp_conf['router'])
            #self._request.emit(packet.__str__())
            send = True
        elif packet.is_dhcp_request_packet():
            log.debug('REQUEST')
            packet.transform_to_dhcp_ack_packet()
            packet.set_option('yiaddr', self.ip_client)
            packet.set_option('siaddr', self.dhcp_conf['router'])
            packet.set_option('router', [self.dhcp_conf['router']], validate=False)
            packet.set_option('domain_name_servers', ['8.8.8.8'], validate=False)
            packet.set_option('ip_address_lease_time', int(self.dhcp_conf['leasetimeMax']))
            if (self.getHostnamePakcet(packet) != None):
                for key in self.leases.keys():
                    for item in self.leases[key].keys():
                        if (self.leases[key][item] == str(self.ip_client)):
                            self.leases[key]['host_name'] = self.getHostnamePakcet(packet)
                            break
            print(self.leases)
            self._request.emit(self.leases[mac])
            send = True
        if send:
            log.debug('SEND to %s:\n%s\n', addr, packet)
            ipaddr, port = addr
            if ipaddr == '0.0.0.0':
                ipaddr = '255.255.255.255'
            addr = (ipaddr, port)
            try:
                self.transport.sendto(packet.encode_packet(), addr)
            except: pass

    def getHostnamePakcet(self, packet):
        for (option_id, data) in sorted(packet._options.items()):
            result = None
            if option_id == 53:  # dhcp_message_type
                pass
            elif option_id == 55:  # parameter_request_list
                pass
            else:
                result = _FORMAT_CONVERSION_DESERIAL[DHCP_OPTIONS_TYPES[option_id]](data)
            if packet._get_option_name(option_id) == 'hostname':
                return result

    def error_received(exc):
        log.error('ERROR', exc_info=exc)


class DHCPThread(QThread):
    sendConnetedClient = pyqtSignal(object)
    def __init__(self,iface,DHCPconf):
        QThread.__init__(self)
        self.iface = iface
        self.dhcp_conf = DHCPconf
        self.DHCPProtocol = DHCPProtocol(self.dhcp_conf, self.sendConnetedClient)
        self.started = False

    def run(self):
        self.started = True
        logging.basicConfig()
        log = logging.getLogger('dhcplib')
        log.setLevel(logging.DEBUG)

        server_address = self.dhcp_conf['router']
        server_port = 67
        client_port = 68

        #log.debug('Listen on %s:%s (-> %s)', server_address, server_port, client_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', server_port))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,  str(self.iface + '\0').encode())


        #self.DHCP._request.connect(self.get_DHCP_Response)
        self.DHCPProtocol.connection_made(self.sock)
        #log.debug("Starting UDP server")
        while self.started:
            message, address = self.sock.recvfrom(1024)
            self.DHCPProtocol.datagram_received(message, address)

    def stop(self):
        self.started = False
        self.sock.close()
