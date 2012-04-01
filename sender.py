#!/usr/bin/python

import os
from random import randint

from scapy.all import *
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor

from config import *
from utils import *


class TcpSession:
    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.ip = IP(src=src, dst=dst)
        self.seq = randint(10, 100) * 1000 # zero-ended for simplicity in debug time


    def connect(self):
        SYN = TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.seq)
        send(self.ip/SYN)
        self.seq += 1


    def ack(self, ack_seq):
        pkt_to_send = self.ip / TCP(sport=self.sport, dport=self.dport, flags="A",
                                    seq=self.seq, ack=ack_seq)
        send(pkt_to_send)


    def close(self, ack_seq):
        pkt_to_send = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA",
                                    seq=self.seq, ack=ack_seq)
        send(pkt_to_send)


    def push(self, ack_seq, data):
        payload = Raw(data)
        pkt_to_send = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA",
                                    seq=self.seq, ack=ack_seq) / payload
        self.seq += 1 + len(payload)
        send(pkt_to_send)


class SendProxyServer(LineReceiver):

    def __init__(self):
        self.connections = {}


    def connectionMade(self):
        print "%s:%d connected." % self.transport.client
        self.sendLine("HELLO %s" % self.transport.client[0]) #XXX


    def lineReceived(self, line):
        parts = line.split('\t')
        if parts[0] == "CONNECT":
            self.handle_CONNECT(*parts[1:])
        elif parts[0] == "ACK":
            self.handle_ACK(*parts[1:])
        elif parts[0] == "CLOSE":
            self.handle_CLOSE(*parts[1:])
        elif parts[0] == "PUSH":
            self.handle_PUSH(*parts[1:])


    def handle_CONNECT(self, src, dst, sport, dport):
        sport = int(sport)
        dport = int(dport)
        self.connections[sport] = TcpSession(src, dst, sport, dport)
        self.connections[sport].connect()


    def handle_ACK(self, sport, ack_seq):
        sport = int(sport)
        ack_seq = int(ack_seq)
        if sport in self.connections:
            session = self.connections[sport]
            session.ack(ack_seq)
        else:
            print "Ooops! ACK for invalid connection: sport=%d, ack_seq=%d" % (sport, ack_seq)


    def handle_CLOSE(self, sport, ack_seq):
        sport = int(sport)
        ack_seq = int(ack_seq)
        if sport in self.connections:
            session = self.connections[sport]
            session.close(ack_seq)
            del self.connections[sport]
            self.sendLine("%d CLOSE" % sport)
        else:
            print "Ooops! CLOSE for invalid connection: sport=%d, ack_seq=%d" % (sport, ack_seq)


    def handle_PUSH(self, sport, ack_seq, *data):
        sport = int(sport)
        ack_seq = int(ack_seq)
        if sport in self.connections:
            session = self.connections[sport]
            session.push(ack_seq, '\n'.join(data))
        else:
            print "Ooops! PUSH for invalid connection: sport=%d, ack_seq=%d" % (sport, ack_seq)


class SendProxyServerFactory(Factory):

    def buildProtocol(self, addr):
        return SendProxyServer()


reactor.listenTCP(SEND_PROXY_PORT, SendProxyServerFactory())
reactor.run()
