#!/usr/bin/python

import os
from random import randint

from scapy.all import *
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor

from utils import *


class TcpSession:
    def __init__(self, src, dst, sport, dport):
        self.state = "STARTING"
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.ip = IP(src=src, dst=dst)
        self.seq = randint(10, 100) * 1000 # zero-ended for simplicity in debug time

    def connect(self):
        SYN = TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.seq)
        send(self.ip/SYN)


class SendProxyServer(LineReceiver):

    def __init__(self):
        self.connections = {}

    def connectionMade(self):
        self.sendLine("HELLO :)")

    def lineReceived(self, line):
        parts = line.split()
        if parts[0] == "CONNECT":
            self.handle_CONNECT(*parts[1:])

    def handle_CONNECT(self, src, dst, sport, dport):
        sport = int(sport)
        dport = int(dport)
        self.connections[sport] = TcpSession(src, dst, sport, dport)
        self.connections[sport].connect()

        # TOD:
        self.sendLine("%d CLOSE" % sport)


class SendProxyServerFactory(Factory):

    def buildProtocol(self, addr):
        return SendProxyServer()


reactor.listenTCP(9090, SendProxyServerFactory())
reactor.run()
