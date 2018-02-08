import os
import datetime
from parse import compile
from collections import namedtuple
from prettytable import PrettyTable
from flask_table import Table, Col, LinkCol
from flask import Flask, render_template, request, Markup, jsonify, escape
from werkzeug.utils import secure_filename
import pickle
import re
import sys
import socket
import requests





UPLOAD_FOLDER = '/Users/bluck/PycharmProjects/expressway-mra-callflow/uploaded_files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

gProxyLegMap = {}
gProxyLegMapE = {}
gProxyLegMapC = {}
gCurrentThisInstance = {}
gFsmTable = None
gLogList = []
gManipulatorMap = {}
gPacketRelayMapE = {}
gPacketRelayMapC = {}
gPacketRelayMapTurn = {}
gExpEIP, gExpCIP, gCucmIP, gExpCInternalIP = None, None, None, None
gRouteMapE, gRouteMapC = None, None
gProxyList = None
gCallList = None
gCurrFilename, gCurrLinenum = None, None
gPortAssignment = {}
gB2buaPortAssignment = {}
gCallIDMap = {}
gCallIDtoSessionID = {}
gCallIDtoRemoteSessionID = {}
gLastReqSent = None
gPhone1IP = None

def timestamp_url_handler(error, endpoint, values):
    # build the url to use in the timestamp link in the message flow table. The Flask Table package uses
    # Flask's url_for() function but this expects a known endpoint declared in the annotations. If not found,
    # will raise an error. This is the error handler that will return our fixed '#' url because we don't
    # want to call out to anything, just handle it with a jquery event and scroll the log file.
    if endpoint == '#':
        return '#' + values.get('filename') + '#' + str(values.get('linenum'))
    else:
        # Some other endpoint, re-raise the BuildError, in context of original traceback.
        exc_type, exc_value, tb = sys.exc_info()
        if exc_value is error:
            raise exc_type, exc_value, tb
        else:
            raise error

# add the url error handler
app.url_build_error_handlers.append(timestamp_url_handler)

SipProxyLegSet = set()
ProxyNamedTuple = namedtuple('ProxyNamedTuple', 'this individNum direction fromNettle toNettle previousHopIP nextHopIP')



class Log:
    def __init__(self, this='', timestamp='', shortLog='', longLog='', direction='', rawTimestamp=None, currLineNum=None, srcEntity=''):
        self.this      = this
        if rawTimestamp is not None:
            # Caller already converted the timestamp
            self.timestamp = rawTimestamp
        else:
            self.timestamp = getTimestamp(timestamp)
        self.shortLog  = shortLog
        self.longLog   = longLog
        self.direction = direction
        if currLineNum is not None:
            # Caller supplied line number
            self.linenum = currLineNum
        else:
            self.linenum   = gCurrLinenum
        self.filename  = gCurrFilename
        self.srcEntity = srcEntity

    def getShortLogHtml(self):
        return self.shortLog.replace(' ', '&nbsp;')


gPrevTimestamp = " "
gSeq = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
gSeqIdx = 0

def getTimestamp(timestamp):
    # Sequence the timestamps if we have duplicates. This ensures they stay in order when sorted by timestamp.
    global gPrevTimestamp, gSeq, gSeqIdx
    if timestamp == gPrevTimestamp:
        if gSeq[gSeqIdx] == 'z':
            print "At the end!"
        timestamp = timestamp + gSeq[gSeqIdx]
        gSeqIdx += 1
    else:
        gPrevTimestamp = timestamp
        timestamp = timestamp + ' '
        gSeqIdx = 0
    return timestamp

def revertTimestamp(timestamp):
    # Undo the sequence we did above, which means just removing the last character
    # Check if this is a timestamp we've doctored
    if timestamp[-1] in gSeq + ' ':
        return timestamp[:-1]
    else:
        return timestamp


def getThisPointer(this):
    global gCurrentThisInstance
    # Given a native 'this' pointer, return a unique value (e.g. 0x55d1c6ae9340-1)
    if gCurrentThisInstance.get(this) is None:
        gCurrentThisInstance[this] = 1
    return this + '-' + str(gCurrentThisInstance[this])

def nextThisPointer(this):
    global gCurrentThisInstance
    # Update the pointer instance. Called after destructor has been parsed.
    if gCurrentThisInstance.get(this) is None:
        print "*** nextThisPointer: unknown this pointer"
    else:
        gCurrentThisInstance[this] += 1




# =====================================================================================================================
#                                                  FSM logs
# =====================================================================================================================

# Starting task execution. Module can be sipproxylegfsm or sipproxymsgdspfsm or other
p_startTask = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.fsm.{module:w}" Level="TRACE" CodeLocation="allshare/fsm/fsmfsm.cpp({line:d})" Method="::sys_testAndExecTask" Thread="{thread:S}":  Detail="Starting message execution on task" Self="{self.specie}:{self.individ_no}" Sender="{sender.specie}:{sender.individ_no}" Msg="{msg}" Task="{task}" State="" NxtState="" NxtStateId="{next_state_id}"')

# Completing task execution
p_completeTask = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.fsm.{module:w}" Level="TRACE" CodeLocation="allshare/fsm/fsmfsm.cpp({line:d})" Method="::sys_testAndExecTask" Thread="{thread:S}":  Detail="Completed message execution on task" Self="{self.specie}:{self.individ_no}" Sender="{sender.specie}:{sender.individ_no}" Msg="{msg}" Task="{task}" State="" NxtState="" NxtStateId="{next_state_id}" Started-task-name="{started_task_name}" Completed-task-name="{completed_task_name}"')
#p_completeTask = compile('Method="::sys_testAndExecTask" Thread="{thread:S}":  Detail="Completed message execution on task" Self="{self.specie}:{self.individ_no}" Sender="{sender.specie}:{sender.individ_no}" Msg="{msg}" Task="{task}" State="" NxtState="" NxtStateId="{next_state_id}" Started-task-name="{started_task_name}" Completed-task-name="{completed_task_name}"')

def parse_startTask(line, currentSpecie, currentIndividNum, senderSpecie, senderIndividNum, currentMsg):
    global gFsmTable
    r = p_startTask.parse(line)
    if r is None:
        return False, currentSpecie, currentIndividNum, senderSpecie, senderIndividNum, currentMsg
    else:
        gFsmTable.add_row(
            [r['timestamp'], r['sender.specie'], r['sender.individ_no'], r['self.specie'], r['self.individ_no'],
             r['msg'], r['next_state_id']])
        if r['sender.specie'] == 'SipProxyLegFsm':
            SipProxyLegSet.add(r['sender.specie'] + ":" + r['sender.individ_no'])

        currentSpecie = r['self.specie']
        currentIndividNum = r['self.individ_no']
        senderSpecie = r['sender.specie']
        senderIndividNum = r['sender.individ_no']
        return True, currentSpecie, currentIndividNum, senderSpecie, senderIndividNum, r['msg']


def parse_completeTask(line):
    r = p_completeTask.search(line)
    if r is None:
        return False
    else:
        # Note that it doesn't matter what the msg is, whatever we were processing is done
        return True



# =====================================================================================================================
#                                          Network Media Routing logs
# =====================================================================================================================

class RouteEvent:
    def __init__(self, timestamp='', action='', extIP1='', extPort1='', extIP2='', extPort2=''):
        self.timestamp = getTimestamp(timestamp)
        self.action = action
        self.extIP1   = extIP1
        self.extPort1 = extPort1
        self.extIP2   = extIP2
        self.extPort2 = extPort2

class Route:
    def __init__(self, timestamp, action, extIP1, extPort1, socket1, ip1, port1, socket2, ip2, port2, extIP2,
                 extPort2, direction=''):
        self.event = []
        self.event.append(RouteEvent(timestamp, action, extIP1, extPort1, extIP2, extPort2))
        self.socket1  = socket1
        self.ip1      = ip1
        self.port1    = port1
        self.socket2  = socket2
        self.ip2      = ip2
        self.port2    = port2
        self.direction = direction


# 2017-12-31T17:34:15.122-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2017-12-31 22:34:15,123" Module="network.mediarouting" Level="DEBUG":  Action="Received" Detail="Route: Creating: Packets Rxd on 10.81.54.5:36072 (socket 0x556a7510b9c0) from UNDEFINED Txd on 10.81.54.5:36000  (socket 0x556a70d11220)  to 10.81.54.102:48446"
p_mediaRoutingCreateIncoming = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  Action="Received" Detail="Route: Creating: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from UNDEFINED Txd on {txIP}:{txPort}  (socket {socket2})  to {toIP}:{toPort}"')

# 2017-12-31T17:34:15.135-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2017-12-31 22:34:15,135" Module="network.mediarouting" Level="DEBUG":  Action="Received" Src-ip="10.81.54.102" Src-port="48446" Detail="Route: Creating: Packets Rxd on 10.81.54.5:36000 (socket 0x556a70d11220) from 10.81.54.102:48446 Txd on 10.81.54.5:36072  (socket 0x556a7510b9c0)  to 10.122.73.183:18160"
# Note, srcInfo seems to replicate the data in fromIP/fromPort
# fromIP/fromPort <--> [rxIP/rxPort ==> txIP/txPort] <--> toIP/toPort
p_mediaRoutingCreateOutgoing = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  Action="Received" {srcInfo} Detail="Route: Creating: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from {fromIP}:{fromPort} Txd on {txIP}:{txPort}  (socket {socket2})  to {toIP}:{toPort}"')

# 2018-01-02T12:47:14.037-05:00 xway-pratco-e1 tvcs: UTCTime="2018-01-02 17:47:14,033" Module="network.mediarouting" Level="DEBUG":  Detail="Route: Deleting: Packets Rxd on 172.18.198.210:36076 (socket 0x562533d27170) from UNDEFINED Txd on 172.18.198.210:2776  (socket 0x56252eb0ccd0)  to 172.18.198.211:48188"
p_mediaRoutingDeleteIncoming = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  Detail="Route: Deleting: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from UNDEFINED Txd on {txIP}:{txPort}  (socket {socket2})  to {toIP}:{toPort}"')

p_mediaRoutingDeleteOutgoing = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  {remoteInfo} Detail="Route: Deleting: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from {fromIP}:{fromPort} Txd on {txIP}:{txPort}  (socket {socket2})  to {toIP}:{toPort}"')


# For TURN media routing logs, the first has fromIP/fromPort but not toIP/toPort. The second has toIP/toPort but not fromIP/fromPort

# 2018-01-05T15:28:25.542-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2018-01-05 20:28:25,542" Module="network.mediarouting" Level="DEBUG":  Action="Received" Src-ip="10.122.73.161" Src-port="19204" Detail="Route: Creating: Packets Rxd on 10.81.54.5:3478 (socket 0x5600d3502860) from 10.122.73.161:19204 Txd on 10.81.54.5:24012  (socket 0x5600d311dc80)  to 0.0.0.0 if destination is in Allowed Peer List"
p_turnRoutingCreateIncoming = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  Action="Received" {srcInfo} Detail="Route: Creating: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from {fromIP}:{fromPort} Txd on {txIP}:{txPort}  (socket {socket2})  to 0.0.0.0 if destination is in Allowed Peer List"')

# 2018-01-05T15:28:25.542-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2018-01-05 20:28:25,542" Module="network.mediarouting" Level="DEBUG":  Action="Received" Src-ip="0.0.0.0" Detail="Route: Creating: Packets Rxd on 10.81.54.5:24012 (socket 0x5600d311dc80) from Allowed Peer List Txd on 10.81.54.5:3478  (socket 0x5600d3502860)  to 10.122.73.161:19204"
p_turnRoutingCreateOutgoing = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  Action="Received" Src-ip="0.0.0.0" Detail="Route: Creating: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from Allowed Peer List Txd on {txIP}:{txPort}  (socket {socket2})  to {toIP}:{toPort}"')

p_turnRoutingDeleteIncoming = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  {remoteInfo} Detail="Route: Deleting: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from {fromIP}:{fromPort} Txd on {txIP}:{txPort}  (socket {socket2})  to 0.0.0.0 if destination is in Allowed Peer List"')

p_turnRoutingDeleteOutgoing = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.mediarouting" Level="DEBUG":  Remote-ip="0.0.0.0" Detail="Route: Deleting: Packets Rxd on {rxIP}:{rxPort} (socket {socket1}) from Allowed Peer List Txd on {txIP}:{txPort}  (socket {socket2})  to {toIP}:{toPort}"')


# Note that the mediaRoutingCreateUndefined log is usually encountered first, but the external ip and port are
# "UNDEFINED" in this log. The mediaRoutingCreate usually comes next and has the same sockets but the external
# ip and port are defined so we can update the entry in the mapping table.

def parse_mediaRoutingCreateIncoming(line, routeMap):
    # This log is for the incoming packets from the endpoint
    r = p_mediaRoutingCreateIncoming.parse(line)
    if r is None:
        return False
    else:
        route = routeMap.get(r['socket1']+r['rxPort']+r['socket2']+r['txPort'])
        if route is None:
            route = Route(r['timestamp2'], 'Create Incoming', 'undef', 'undef', r['socket1'], r['rxIP'], r['rxPort'],
                          r['socket2'], r['txIP'], r['txPort'], r['toIP'], r['toPort'], 'rx')
        else:
            route.event.append(RouteEvent(r['timestamp2'], 'Create Incoming', 'undef', 'undef', r['toIP'], r['toPort']))
        routeMap[r['socket1']+r['rxPort']+r['socket2']+r['txPort']] = route
        return True


def parse_mediaRoutingCreateOutgoing(line, routeMap):
    # This log is for the outgoing packets to the endpoint
    r = p_mediaRoutingCreateOutgoing.parse(line)
    if r is None:
        return False
    else:
        route = routeMap.get(r['socket2']+r['txPort']+r['socket1']+r['rxPort'])
        if route is None:
            route = Route(r['timestamp2'], 'Create Outgoing', r['toIP'], r['toPort'], r['socket2'], r['txIP'], r['txPort'],
                          r['socket1'], r['rxIP'], r['rxPort'], r['fromIP'], r['fromPort'], 'tx')
        else:
            route.event.append(RouteEvent(r['timestamp2'], 'Create Outgoing', r['toIP'], r['toPort'], r['fromIP'], r['fromPort']))
        routeMap[r['socket2']+r['txPort']+r['socket1']+r['rxPort']] = route
        return True


def parse_mediaRoutingDeleteIncoming(line, routeMap):
    r = p_mediaRoutingDeleteIncoming.parse(line)
    if r is None:
        return False
    else:
        route = routeMap.get(r['socket1']+r['rxPort']+r['socket2']+r['txPort'])
        if route is None:
            print "*** parse_mediaRoutingDeleteIncoming: Did not find route"
        else:
            route.event.append(RouteEvent(r['timestamp2'], 'Delete Incoming', 'undef', 'undef', r['toIP'], r['toPort']))
            routeMap[r['socket1']+r['rxPort']+r['socket2']+r['txPort']] = route
        return True


def parse_mediaRoutingDeleteOutgoing(line, routeMap):
    r = p_mediaRoutingDeleteOutgoing.parse(line)
    if r is None:
        return False
    else:
        route = routeMap.get(r['socket2']+r['txPort']+r['socket1']+r['rxPort'])
        if route is None:
            print "*** parse_mediaRoutingDeleteOutgoing: Did not find route"
        else:
            route.event.append(RouteEvent(r['timestamp2'], 'Delete Outgoing', r['toIP'], r['toPort'], r['fromIP'], r['fromPort']))
            routeMap[r['socket2']+r['txPort']+r['socket1']+r['rxPort']] = route
        return True


def parse_turnRoutingCreateIncoming(line, routeMap):
    # This log is for the incoming packets from endpoint to the TURN server
    r = p_turnRoutingCreateIncoming.parse(line)
    if r is None:
        return False
    else:
        route = routeMap.get(r['socket1']+r['socket2'])
        if route is None:
            route = Route(r['timestamp2'], 'Create Incoming', r['fromIP'], r['fromPort'], r['socket1'], r['rxIP'], r['rxPort'],
                          r['socket2'], r['txIP'], r['txPort'], 'undef', 'undef', 'rx')
        else:
            route.event.append(RouteEvent(r['timestamp2'], 'Create Incoming', r['fromIP'], r['fromPort'], 'undef', 'undef'))
        routeMap[r['socket1']+r['socket2']] = route
        return True


def parse_turnRoutingCreateOutgoing(line, routeMap):
    # This log is for the outgoing packets to the endpoint
    r = p_turnRoutingCreateOutgoing.parse(line)
    if r is None:
        return False
    else:
        route = routeMap.get(r['socket2']+r['socket1'])
        if route is None:
            route = Route(r['timestamp2'], 'Create Outgoing', 'undef', 'undef', r['socket1'], r['rxIP'], r['rxPort'],
                          r['socket2'], r['txIP'], r['txPort'], r['toIP'], r['toPort'], 'tx')
        else:
            route.event.append(RouteEvent(r['timestamp2'], 'Create Outgoing', r['toIP'], r['toPort'], 'undef', 'undef'))
        routeMap[r['socket2']+r['socket1']] = route
        return True


def parse_turnRoutingDeleteIncoming(line, routeMap):
    r = p_turnRoutingDeleteIncoming.parse(line)
    if r is None:
        return False
    route = routeMap.get(r['socket1']+r['socket2'])
    if route is None:
        print "*** parse_mediaRoutingDeleteIncoming: Did not find route"
    else:
        route.event.append(RouteEvent(r['timestamp2'], 'Delete Incoming', r['fromIP'], r['fromPort'], 'undef', 'undef'))
        routeMap[r['socket1']+r['socket2']] = route
    return True


def parse_turnRoutingDeleteOutgoing(line, routeMap):
    r = p_turnRoutingDeleteOutgoing.parse(line)
    if r is None:
        return False
    route = routeMap.get(r['socket2']+r['socket1'])
    if route is None:
        print "*** parse_mediaRoutingDeleteIncoming: Did not find route"
    else:
        route.event.append(RouteEvent(r['timestamp2'], 'Delete Outgoing', r['toIP'], r['toPort'], 'undef', 'undef'))
        routeMap[r['socket2']+r['socket1']] = route
    return True



# =====================================================================================================================
#                                 M E D I A   T E R M I N A T I O N   P O I N T
# =====================================================================================================================

# developer.mediarouting.core = TRACE

# The sequence of events to look for are as follows:
#
#   1. p_readDataAvailable1  : the local ip:port we received the packet on
#   2. p_readDataAvailable2  : the remote ip:port that sent the packet to us
#   3. p_forwardPacket       : indicates that we are forwarding the packet; if this doesn't appear I think we drop the packet
#   4. p_sendPacketOnWire    : the local ip:port from which we send the packet
#
# Unfortunately what we don't get from this sequence is the ip:port to which we send the packet. Will see if we can infer that

p_epollin = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="developer.mediarouting.core" Level="DEBUG" CodeLocation="ppcmains/mediarouting/media_forwarding_framework.cpp({line:d})" Method="media_forwarding_framework::handle_events" Thread="{thread:S}": Handle EPOLLIN event for fd: {fd:d}')

p_readDataAvailable1 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="developer.mediarouting.core" Level="TRACE" CodeLocation="ppcmains/mediarouting/TerminationPointBase.cpp({line:d})" Method="TerminationPointBase::readDataAvailable" Thread="{thread:S}": Read UDP packet - socket description: int m_sockfd = {fd:d}, fd_registration * m_powner = {powner:S}, TP_HANDLE m_hself = {hself:S}, m_uprhandle = {upr:S}, bound addr == [{rxip:S}]:{rxport:S}')

p_readDataAvailable2 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="developer.mediarouting.core" Level="DEBUG" CodeLocation="ppcmains/mediarouting/TerminationPointBase.cpp({line:d})" Method="TerminationPointBase::readDataAvailable" Thread="{thread:S}": received from: [{fromip:S}]:{fromport:d}')

p_packetMatchesRoute = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="developer.mediarouting.core" Level="DEBUG" CodeLocation="ppcmains/mediarouting/unidirectional_packet_router.cpp({line:d})" Method="unidirectional_packet_router::packetMatchesRoute" Thread="{thread:S}": unidirectional_packet_router::packetMatchesRoute {result:w}')

p_forwardPacket = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="developer.mediarouting.core" Level="DEBUG" CodeLocation="ppcmains/mediarouting/unidirectional_packet_router.cpp({line:d})" Method="unidirectional_packet_router::forwardPacket" Thread="{thread:S}": Actually send the packet')

p_sendPacketOnWire = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {application:S}: UTCTime="{date2:S} {timestamp2:S}" Module="developer.mediarouting.core" Level="TRACE" CodeLocation="ppcmains/mediarouting/TerminationPointBase.cpp({line:d})" Method="TerminationPointBase::sendPacketOnWire" Thread="{thread:S}": Send UDP data, description: int m_sockfd = {fd:d}, fd_registration * m_powner = {powner:S}, TP_HANDLE m_hself = {hself:S}, m_uprhandle = {upr:S}, bound addr == [{txip:S}]:{txport:d}')

# Track the individual media handler threads and associate the file descriptors each thread is managing
class MediaThread:
    def __init__(self, timestamp='', thread=''):
        self.timestamp = getTimestamp(timestamp)
        self.thread    = thread
        self.fileDescriptors = set()

    def addFileDescriptor(self, fd):
        self.fileDescriptors.add(fd)

def parse_epollin(line, mediaThreadMap):
    # Use the EPOLLIN log to assicate an FD with a thread
    r = p_epollin.search(line)
    if r is None:
        return False
    timestamp = r['timestamp2']
    thread = r['thread']
    fd     = str(r['fd'])
    mediaThread = mediaThreadMap.get(thread)
    if mediaThread is None:
        mediaThread = MediaThread(timestamp, thread)
    mediaThread.addFileDescriptor(fd)
    mediaThreadMap[thread] = mediaThread
    return True

def getMediaThreadTable(mediaThreadMap):
    table = PrettyTable(['Timestamp', 'Thread', 'FDs'])
    for thread in mediaThreadMap.values():
        table.add_row([thread.timestamp, thread.thread, thread.fileDescriptors])
    return table

class PacketRelayConnection:
    def __init__(self, timestamp='', rxFD='', fromIP='', fromPort='', rxIP='', rxPort='', txFD='', txIP='', txPort='', toIP='', toPort='', numTries=0, numTries2=0, numTries3=0):
        self.timestamp = getTimestamp(timestamp)
        self.rxFD     = rxFD
        self.fromIP   = fromIP
        self.fromPort = fromPort
        self.rxIP     = rxIP
        self.rxPort   = rxPort
        self.txFD     = txFD
        self.txIP     = txIP
        self.txPort   = txPort
        self.toIP     = toIP
        self.toPort   = toPort
        self.maxTries = numTries
        self.numPackets = 0

    def newPacket(self, timestamp, numTries=0):
        if numTries > self.maxTries:
            self.maxTries = numTries
            self.timestamp = getTimestamp(timestamp)
        self.numPackets += 1


def parse_readDataAvailable(line, f, packetRelayMap):
    r = p_readDataAvailable1.search(line)
    if r is None:
        return False

    # Got the file descriptor and local IP and port where the packet came in on
    rxFD   = str(r['fd'])
    rxIP   = r['rxip']
    rxPort = str(r['rxport'])
    timestamp = r['timestamp2']

    line = f.next()
    r = p_readDataAvailable2.search(line)
    if r is None:
        print "*** parse_readDataAvailable: Didn't get the next readDataAvailable log"
        print line
        return True

    fromIP   = r['fromip']
    fromPort = str(r['fromport'])

    # Packet was forwarded, so now we expect it to be sent on the wire
    numTries = 0
    r = None
    for line in f:
        numTries += 1
        # We're done with this packet if we run into another EPOLLIN
        if 'EPOLLIN' in line:
            break
        r = p_forwardPacket.search(line)
        if r is not None:
            break

    if r is None:
        # This is an expected case, happens when we receive a packet but the rout isn't set up yet
        #print "*** parse_readDataAvailable: Didn't get forwardPacket log"
        #print line
        return True

    # On the E, we get a sendPacketOnWire() log after forwardPacket, but on the C we don't, so treat it as optional
    line = f.next()
    r = p_sendPacketOnWire.search(line)
    txFD = ''
    txIP = ''
    txPort = ''
    if r is not None:
        txFD   = str(r['fd'])
        txIP   = r['txip']
        txPort = str(r['txport'])

    key = rxFD + rxPort + txFD + txPort
    prc = packetRelayMap.get(key)
    if prc is None:
        prc = PacketRelayConnection(timestamp, rxFD, fromIP, fromPort, rxIP, rxPort, txFD, txIP, txPort, '', '', numTries)
        packetRelayMap[key] = prc
    prc.newPacket(timestamp, numTries)
    return True

def scrubPacketRelayData(packetRelayMap):
    # Fill in the rightSocket's toIP and toPort using the fromIP and fromPort of that same socket when its on the left.
    for rightSocket in packetRelayMap.values():
        # Skip entries where I think probes are being exchanged
        if rightSocket.rxFD == rightSocket.txFD:
            continue
        for leftSocket in packetRelayMap.values():
            if leftSocket.rxFD == leftSocket.txFD:
                continue
            if leftSocket.rxFD == rightSocket.txFD and leftSocket.txFD == rightSocket.rxFD:
                # We have a match
                rightSocket.toIP = leftSocket.fromIP
                rightSocket.toPort = leftSocket.fromPort

    # Not build a new table that shows end-to-end packet routing

def getPacketRelayTable(packetRelayMap):
    # Fill in additional fields in the map that don't come from the logs
    scrubPacketRelayData(packetRelayMap)
    packetRelayTable = PrettyTable(['Timestamp', 'fromIP', 'fromPort', 'rxIP', 'rxPort', 'rxFD', 'txFD', 'txPort', 'txIP', 'toPort', 'toIP', 'numPackets', 'maxTries'])
    for pt in packetRelayMap.values():
        packetRelayTable.add_row([pt.timestamp, pt.fromIP, pt.fromPort, pt.rxIP, pt.rxPort, pt.rxFD, pt.txFD, pt.txPort, pt.txIP, pt.toPort, pt.toIP, pt.numPackets, pt.maxTries])
    return packetRelayTable



# =====================================================================================================================
#                                         S I P   P R O X Y   L E G S
# =====================================================================================================================

class ProxyLeg:
    order = 0
    def __init__(self, this='', individNum='', direction='',
                 fromNettle='', toNettle='', fromIP='', toIP='', otherLeg='',
                 sipRequest='', isInvite=False, cancelled=False):
        self.this = this
        self.individNum = individNum
        self.direction = direction
        self.fromNettle = fromNettle
        self.toNettle = toNettle
        self.fromIP = fromIP
        self.toIP = toIP
        self.otherLeg = otherLeg
        self.sipRequest = sipRequest
        self.isInvite = isInvite
        self.cancelled = cancelled
        self.currentResponseCode = None
        self.mediaManipulatorThis = None
        self.callID = None
        self.sessionID = None
        self.remoteSessionID = None
        self.mediaManipulatorType = []
        self.order = ProxyLeg.order
        ProxyLeg.order += 1

    def session(self):
        if self.sessionID is None or self.remoteSessionID is None:
            return ''
        else:
            return self.sessionID + self.remoteSessionID

class Proxy:
    def __init__(self, num=0, inboundLeg='', outboundLeg='',
                 inboundFsm='', outboundFsm='', fromIP='', toIP='',
                 fromNettle='', toNettle='', inboundMedia='', outboundMedia=''):
        self.num = num
        self.inboundLeg = inboundLeg
        self.outboundLeg = outboundLeg
        self.inboundFsm = inboundFsm
        self.outboundFsm = outboundFsm
        self.fromIP = fromIP
        self.toIP = toIP
        self.fromNettle = fromNettle
        self.toNettle = toNettle
        self.inboundMedia = inboundMedia
        self.outboundMedia = outboundMedia

class Call:
    def __init__(self, sessionId=None, remoteSessionId=None):
        self.sessionID = sessionId
        self.remoteSessionID = remoteSessionId
        self.proxyList = [Proxy() for i in range(6)]

    def session(self):
        if self.sessionID is None or self.remoteSessionID is None:
            return ''
        else:
            return self.sessionID + self.remoteSessionID

# INBOUND LEGS
# Here's the sequence of parsers relative to the FSM message execution:
#
#     p_inboundNettleAndSrcIP
#     p_ProcessInviteRequest
#   Msg="ProcessInviteRequest" or "ProcessNonInviteRequest"
#     p_inboundProcessInitialRequest
#
#   After the first INVITE is processed
#     p_DisplayResponseInfo
#     p_ReallySendSipRequest
#
# Note that there is nothing that tells us what kind of non-INVITE message it is. We'll have to rely on the outbound
# leg to tell us that, if we care.

# This is printed before the FSM message execution
#p_inboundNettleAndSrcIP = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" {codeLocation} Method="SipProxyLeg::SipProxyLeg" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" Set mNettleLeg="{nettleLeg}" origIngressZoneId="{origZoneId}" from origin="{fromIP}:{fromPort}"')
p_inboundNettleAndSrcIP = compile('Method="SipProxyLeg::SipProxyLeg" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" Set mNettleLeg="{nettleLeg}" origIngressZoneId="{origZoneId}" from origin="{fromIP}:{fromPort}"')

p_ProcessInviteRequest = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::processInviteRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" transactionId={transactionId}')

p_inboundProcessInitialRequest = compile('Method="SipProxyLeg::processInitialRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" transactionId={transactionId}, bAuthenticated=YES')
#p_inboundProcessInitialRequest = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::processInitialRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" transactionId={transactionId}, bAuthenticated=YES')

p_ProcessSubsequentRequest = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::processSubsequentRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" transactionId={transactionId}, bAuthenticated={auth}, rAuthUsernam=')

p_ProcessAckWithSdpRequest = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::processAckWithSdpRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" transactionId={transactionId}')

#p_DisplayResponseInfo = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::displayResponseInfo" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" {responseType} response {responseCode} for request {requestName}')
p_DisplayResponseInfo = compile('Method="SipProxyLeg::displayResponseInfo" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" {responseType} response {responseCode} for request {requestName}')

p_ReallySendSipRequest = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::reallySendSipRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" rRequestPackage=(mRequest.methodName={requestName}, mTransactionId={transactionId}, &mrLeg={mrLeg})')

p_SendStatefulResponseDirectly = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::sendStatefulResponseDirectly" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" Sending {respType} response={responseCode} for transactionId={transactionId}')

# The following appear after displayResponseInfo on the leg that receives the response. The first pattern should match
# the other 3 below.
p_processResponse = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::process{respType}Response" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" cookie={cookie:S}') # The :S is needed to match on non-white-space since no other characters will match

# The following are for reference
p_processSuccessfulInviteResponse = compile('2017-12-31T17:34:15.094-05:00 vm-bluck-fed-cust2-vcsc1 tvcs: UTCTime="2017-12-31 22:34:15,073" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp(2608)" Method="SipProxyLeg::processSuccessfulInviteResponse" Thread="0x7f50e82ac700":  this="0x5596ab2c4810" Type="Outbound" cookie=47647')

p_processProvisionalResponse = compile('2017-12-31T17:34:15.189-05:00 vm-bluck-fed-cust2-vcsc1 tvcs: UTCTime="2017-12-31 22:34:15,189" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp(2543)" Method="SipProxyLeg::processProvisionalResponse" Thread="0x7f50e82ac700":  this="0x5596a98cb350" Type="Outbound" cookie=47667')

p_processSuccessfulByeResponse = compile('2017-12-31T17:34:18.460-05:00 vm-bluck-fed-cust2-vcsc1 tvcs: UTCTime="2017-12-31 22:34:18,460" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp(2640)" Method="SipProxyLeg::processSuccessfulByeResponse" Thread="0x7f50e82ac700":  this="0x5596a7a97300" Type="Inbound" cookie=47674')

p_getRequiredLicensingType = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::getRequiredLicensingType" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" Callid from sip SIP CallID="{callid:S}"')



# =================================================
# ================= OUTBOUND LEGS =================

# Here's the sequence of parsers relative to the FSM message execution:
#
#   Msg="Run"
#     p_outboundSendSipRequest
#     p_outboundSetNextHop
#     p_outboundRouteViaNettle
#   Msg="SendInviteWithSdpRequest" or Msg="SendInviteRequest" (only for non-cancelled INVITE legs, not for REGISTER, etc.)
#     p_outboundIsTraversal
#   Msg="Timeout"  (only for cancelled legs)
#     p_outboundTimeout
#
# The timeout message is NOT after the "Run" message, this will need to be scanned for continuously.

# For outbound legs, this is the first SipProxyLeg log after starting message execution on msg "Run"
p_outboundSendSipRequest = compile('Method="SipProxyLeg::sendSipRequest" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" rRequest={sipRequest}, transactionId={transaction}, rRequestor={requestor:S}')  # :S is needed here to specify non-whitespace because this is the end of the line and the parser doesn't have anything else to match on to find the end of the string

# For outbound legs this log identifies the next hop
p_outboundSetNextHop = compile('Method="SipProxyLeg::setNextHopFromUrl" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" setNextHopAddr: address="{nextHopIP}:{nextHopPort}/{nextHopTransport}"')

# For outbound legs this log identifes nettle and a bunch of other stuff. Works for early and delayed media (with and without SDP)
p_outboundRouteViaNettle = compile('Method="SipProxyLeg::routeViaNettleIfNeeded" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}"  routingViaNettle="{routingViaNettle}"  twoInARow="{towInARow}" oneIsATraversalServerZone="{oneIsATraversalServerZone}" isCall="{isCall}" isRefer="{isRefer}" fromClusterPeer="{fromClusterPeer}" fromNettle="{fromNettle}" toNettle="{toNettle}" inboundZone={inboundZone} ({inboundZoneSettings} ) outboundZone={outboundZone} ({outboundZoneSettings} ) CryptoRequired="{cryptoRequired}" ICERequired="{iceRequired}" ReferTerminationRequired="{referTerminationRequired}" TranslateFromMicrosoftRequired="{TranslateFromMicrosoftRequired}" TranslateToMicrosoftRequired="{TranslateToMicrosoftRequired}" routeViaNettle="{routeViaNettle}"')

p_outboundIsTraversal = compile('Method="SipProxyLeg::isTraversalForBandwidth" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}"  isTraversalForBandwidth="{isTraversalForBandwidth}": mstbTakeMedia->getVal()="{takeMedia}" isNettleLeg()="{isNettle}" otherLeg->isNettleLeg()="{otherLegIsNettle}"')

# For outbound legs that are cancelled, this is logged. This will be used to flag a cancelled outbound INVITE leg.
p_outboundTimeout = compile('Method="SipProxyLeg::SIPPROXYLEGFSM_doTimeout" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" status update timer fired')

p_apparent = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::calculateApparentAddressUri" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" apparentAddress={apparent_address:S}, transport={transport:S}')

p_destructor = compile('Method="SipProxyLeg::~SipProxyLeg" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}" Destructor')

# ==========================================================
# Proxy Leg logs
# ==========================================================

def parse_inboundNettleAndSrcIP(line):
    r = p_inboundNettleAndSrcIP.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is not None:
            # This should be the first SipProxyLeg log for the inbound leg
            print this + " parse_inboundNettleAndSrcIP: *** Found a proxy leg that we didn't expect"
            print line
        else:
            proxyLeg = ProxyLeg(this, '0', r['direction'], r['nettleLeg'], 'false', r['fromIP'], '0.0.0.0')
            gProxyLegMap[this] = proxyLeg
        return True


def parse_outboundSendSipRequest(line, currentIndividNum):
    r = p_outboundSendSipRequest.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        requestor = getThisPointer(r['requestor'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is not None:
            # This should be the first SipProxyLeg log for the outbound leg
            print this + " parse_outboundSendSipRequest: *** Found a proxy leg that we didn't expect"
            print line
        else:
            proxyLeg = ProxyLeg(this, currentIndividNum, r['direction'], 'false', 'false', '0.0.0.0', '0.0.0.0',
                                requestor, r['sipRequest'])
            if r['sipRequest'] == 'INVITE':
                proxyLeg.isInvite = True
            gProxyLegMap[this] = proxyLeg

            # check if the other leg exists, if so, set *its* other leg
            otherProxyLeg = gProxyLegMap.get(requestor)
            if otherProxyLeg is not None:
                otherProxyLeg.otherLeg = this
                gProxyLegMap[requestor] = otherProxyLeg
        return True


def parse_outboundTimeout(line):
    r = p_outboundTimeout.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            print this + " parse_outboundTimeout : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            proxyLeg.cancelled = True
            gProxyLegMap[this] = proxyLeg
        return True


def parse_apparent(line):
    r = p_apparent.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            print this + " parse_apparent : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            gLogList.append(Log(this, r['timestamp2'], 'apparent ' + r['apparent_address'], 'calculateApparentAddressUri()'))
        return True


def parse_destructor(line):
    r = p_destructor.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)

        # This is the destructor so we should have already recorded this one
        if proxyLeg is None:
            print this + " p11 : *** Found a destructor for a 'this' pointer that isn't on our list."
            print line

        # Increment the unique-ifier
        nextThisPointer(r['this'])

        return True


def parse_ProcessInviteRequest(line):
    global gLogList
    r = p_ProcessInviteRequest.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_ProcessInviteRequest : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            # Update the proxy leg indicating that it is handling an INVITE
            proxyLeg.sipRequest = 'INVITE'
            proxyLeg.isInvite = True
            gProxyLegMap[this] = proxyLeg

            if r['direction'] == 'Inbound':
                log = Log(this, r['timestamp2'], '-> INVITE', 'processInviteRequest()')
            else:
                log = Log(this, r['timestamp2'], 'INVITE <-', 'processInviteRequest()')

            gLogList.append(log)

        return True


def parse_inboundProcessInitialRequest(line, currentIndividNum, currentMsg):
    r = p_inboundProcessInitialRequest.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_inboundProcessInitialRequest : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            # We should have an FSM individ num for this proxy leg
            if currentIndividNum is not None:
                # Only set the individ num once, no need to risk overwriting with the wrong number
                if proxyLeg.individNum == '0':
                    proxyLeg.individNum = currentIndividNum

            # Set if it is non-invite
            if currentMsg == 'ProcessInviteRequest':
                proxyLeg.sipRequest = 'INVITE'
                proxyLeg.isInvite = True

            gProxyLegMap[this] = proxyLeg

        return True


def parse_ProcessSubsequentRequest(line):
    # This is most likely an ACK. Unfortunately there's nothing in the logs that tell exactly what this subsequent
    # request is, we have to infer it. We do know its not an INVITE because the FSM signal we checked before calling
    # this function indicated it was non-invite.
    global gLogList
    r = p_ProcessSubsequentRequest.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_ProcessSubsequentRequest : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if r['direction'] == 'Inbound':
                log = Log(this, r['timestamp2'], '-> ACK without SDP', 'processSubsequentRequest()')
            else:
                log = Log(this, r['timestamp2'], 'ACK without SDP <-', 'processSubsequentRequest()')
            gLogList.append(log)
        return True

def parse_ProcessAckWithSdpRequest(line):
    # Unlike an ACK without SDP, an ACK with SDP has a named function log that we can match on. The ACK without SDP
    # will hit parse_ProcessSubsequentRequest above.
    r = p_ProcessAckWithSdpRequest.parse(line)
    global gLogList
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_ProcessAckWithSdpRequest : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if r['direction'] == 'Inbound':
                log = Log(this, r['timestamp2'], '-> ACK with SDP', 'processAckWithSdpRequest()')
            else:
                log = Log(this, r['timestamp2'], 'ACK with SDP <-', 'processAckWithSdpRequest()')
            gLogList.append(log)
        return True


def parse_DisplayResponseInfo(line):
    r = p_DisplayResponseInfo.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_DisplayResponseInfo : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            # Save the current response code to use in parse_processResponse method below. This tells us which
            # response code is being processed. Because DisplayResponseInfo is called for both sending and receiving,
            # we don't know at this point where to put the arrow.
            proxyLeg.currentResponseCode = r['responseCode']
            gProxyLegMap[this] = proxyLeg

        return True


def parse_processResponse(line):
    global gLogList
    r = p_processResponse.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_processResponse : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if proxyLeg.currentResponseCode is not None:
                if '100' in proxyLeg.currentResponseCode:
                    # Ignore 100 Trying, they clutter the flow
                    return True

                # This leg is receiving the response code so print the arrow accordingly
                if proxyLeg.direction == 'Inbound':
                    log = Log(this, r['timestamp2'], '-> ' + proxyLeg.currentResponseCode, 'process%sResponse()' % (r['respType']))
                else:
                    log = Log(this, r['timestamp2'], proxyLeg.currentResponseCode + ' <-', 'process%sResponse()' % (r['respType']))
                gLogList.append(log)
                proxyLeg.currentResponseCode = None
                gProxyLegMap[this] = proxyLeg
        return True


def parse_ReallySendSipRequest(line):
    global gLogList
    r = p_ReallySendSipRequest.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_ReallySendSipRequest : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if r['direction'] == 'Inbound':
                log = Log(this, r['timestamp2'], '<- ' + r['requestName'], 'reallySendSipRequest()')
            else:
                log = Log(this, r['timestamp2'], r['requestName'] + ' ->', 'reallySendSipRequest()')

            gLogList.append(log)
        return True


def parse_SendStatefulResponseDirectly(line):
    global gLogList
    r = p_SendStatefulResponseDirectly.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_SendStatefulResponseDirectly : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if '100' in r['responseCode']:
                # Ignore 100 Trying, doesn't help with troubleshooting and clutters up the flow
                return True
            if r['direction'] == 'Inbound':
                log = Log(this, r['timestamp2'], '<- ' + r['responseCode'], 'sendStatfulResponseDirectly(%s)' % r['responseCode'])
            else:
                log = Log(this, r['timestamp2'], r['responseCode'] + ' ->', 'sendStatfulResponseDirectly(%s)' % r['responseCode'])

            gLogList.append(log)
        return True


def parse_outboundSetNextHop(line):
    r = p_outboundSetNextHop.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg, this is the second log expected after SendSipRequest
            print this + " parse_outboundSetNextHop : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if proxyLeg.direction != r['direction']:
                print this + " parse_outboundSetNextHop old direction " + proxyLeg.direction + " new direction " + r['direction']
                print line
            proxyLeg.toIP = r['nextHopIP']
            gProxyLegMap[this] = proxyLeg
        return True


def parse_outboundRouteViaNettle(line):
    r = p_outboundRouteViaNettle.search(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg, this is the third log expected after SetNextHop
            print this + " parse_outboundSetNextHop : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            if proxyLeg.direction != r['direction']:
                print this + " parse_outboundRouteViaNettle old direction " + proxyLeg.direction + " new direction " + r['direction']
                print line
            proxyLeg.fromNettle = r['fromNettle']
            proxyLeg.toNettle = r['toNettle']
            gProxyLegMap[this] = proxyLeg
        return True

def parse_getRequiredLicensingType(line):
    # We use this log to associate the SIP Call-ID to the proxy leg
    r = p_getRequiredLicensingType.parse(line)
    if r is None:
        return False
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print this + " parse_getRequiredLicensingType : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            proxyLeg.callID = r['callid']
            if proxyLeg.sessionID is None:
                proxyLeg.sessionID = gCallIDtoSessionID.get(proxyLeg.callID)
            if proxyLeg.remoteSessionID is None:
                proxyLeg.remoteSessionID = gCallIDtoRemoteSessionID.get(proxyLeg.callID)
        return True

# ====================================================================================================================
#                                    M E D I A   M A N I P U L A T O R S
# ====================================================================================================================

# Media Manipulator logs that have 'this' pointer. To get the first 'this' pointer need to use proximity to the
# SIP proxy leg log that comes before it. Looks like its the SipProxyLeg::isMediaRouted log but any log will do, just
# have to keep track of which proxy leg is running and make the connection.
#
# SipProxyLeg::isMediaRouted ->
#   MediaManipulatorFactory::createInstance
#   SipSdpManipulator::SipSdpManipulator
#     this -> AssentServerSipSdpManipulator::AssentServerSipSdpManipulator
#          -> SipSdpManipulator::allocateMediaHalfIfRequired (media half requested)
#          -> SipSdpManipulator::allocateMediaHalfIfRequired (media half already exists)
#          -> SipSdpManipulator::mediaHalfAllocationSuccess
#          -> AssentServerSipSdpManipulator::~AssentServerSipSdpManipulator
#          -> SipSdpManipulator::releaseMediaHalfT
#          -> SipSdpManipulator::~SipSdpManipulator
#

#p_isMediaRouted = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipProxyLeg.cpp({line:d})" Method="SipProxyLeg::isMediaRouted" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}"  isMediaRouted="{isMediaRouted}": mstbTakeMedia->getVal()="{takeMedia}"')
p_isMediaRouted = compile('Method="SipProxyLeg::isMediaRouted" Thread="{thread:S}":  this="{this:S}" Type="{direction:S}"  isMediaRouted="{isMediaRouted}": mstbTakeMedia->getVal()="{takeMedia}"')

#p_mediaManipulatorCreateInstance = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/MediaManipulatorFactory.cpp({line:d})" Method="MediaManipulatorFactory::createInstance" Thread="{thread:S}": &rMediaSessionMgr={msm}, &rStatusMgr={sm}, bRouteMedia={routeMedia}, eType={manipulatorType}, rCallSerialNumber={callSN}, bIsNatted={isNatted}, branchId={brId}, rIPNetwork=\'IPv4\' m_remoteAddress: [\'IPv4\'\'{transport}\'\'{remoteAddr}\'] (best local: {localIP} -> remote: {remoteIP}), zone={zone}, eMediaRoutingMode={mrm}, pBandwidthManipulator={bwm}, bDecryptMedia={decryptMedia}, mffh={mffh}, nettleLeg={nettleLeg}, passthruLeg={passthroughLeg}')
p_mediaManipulatorCreateInstance = compile('Method="MediaManipulatorFactory::createInstance" Thread="{thread:S}": &rMediaSessionMgr={msm}, &rStatusMgr={sm}, bRouteMedia={routeMedia}, eType={manipulatorType}, rCallSerialNumber={callSN}, bIsNatted={isNatted}, branchId={brId}, rIPNetwork=\'IPv4\' m_remoteAddress: [\'IPv4\'\'{transport}\'\'{remoteAddr}\'] (best local: {localIP} -> remote: {remoteIP}), zone={zone}, eMediaRoutingMode={mrm}, pBandwidthManipulator={bwm}, bDecryptMedia={decryptMedia}, mffh={mffh}, nettleLeg={nettleLeg}, passthruLeg={passthroughLeg}')

#p_sdpMediaManipulatorConstructor = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipSdpManipulator.cpp({line:d})" Method="SipSdpManipulator::SipSdpManipulator" Thread="{thread:S}":  this="{this:S}" Constructor , rCallSerialNumber={callSN}, branchId={brId}, rIPNetwork=\'IPv4\' m_remoteAddress: [\'IPv4\'\'{transport}\'\'{remoteAddr}\'] (best local: {localIP} -> remote: {remoteIP}), pBandwidthManipulator={bwm} mSdpSRTPEncryptionManager="mEncryptionTraits = mbDecryptMedia = {decryptMedia} mbMicrosoftSRTP = {microsoft} InterworkingEncryptionReplayProtectionMode = {protectionMode}"')

# The following constructor gives the manipulator type more accurately than createInstance above.
p_sdpMediaManipulatorConstructor2 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/{manipulatorType}SipSdpManipulator.cpp({line:d})" Method="{manipulatorType}SipSdpManipulator::{manipulatorType}SipSdpManipulator" Thread="{thread:S}":  this="{this:S}" Constructor{remainder}')

#p_sdpMediaManipulatorConstructor2 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/{manipulatorType}SipSdpManipulator.cpp({line:d})" Method="{manipulatorType}SipSdpManipulator::{manipulatorType}SipSdpManipulator" Thread="{thread:S}":  this="{this:S}" Constructor &rMediaSessionManager={msm}, zone={zone}, rCallSerialNumber={callSN}, branchId={brId}, rIPNetwork=\'IPv4\' m_remoteAddress: [\'IPv4\'\'{transport}\'\'{remoteAddr}\'] (best local: {localIP} -> remote: {remoteIP}), pBandwidthManipulator={bwm}')

#p_sdpMediaManipulatorConstructor3 = compile('2017-12-31T17:34:12.609-05:00 vm-bluck-fed-cust2-vcsc1 tvcs: UTCTime="2017-12-31 22:34:12,611" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/AssentClientSipSdpManipulator.cpp(33)" Method="AssentClientSipSdpManipulator::AssentClientSipSdpManipulator" Thread="0x7f50e82ac700":  this="0x5596aae53a20" Constructor &rMediaSessionManager=0x5596a4a66f80, rCallSerialNumber=86feb1d0-82ff-4ee9-a0bf-e02f0d816a7f, branchId=0, rIPNetwork=\'IPv4\' m_remoteAddress: [\'IPv4\'\'TCP\'\'10.81.54.5:7002\'] (best local: 10.81.54.102 -> remote: 10.81.54.5), pBandwidthManipulator=0')

p_mediaHalfRequested = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipSdpManipulator.cpp({line:d})" Method="SipSdpManipulator::allocateMediaHalfIfRequired" Thread="{thread:S}":  this="{this:S}" Media half requested mediaLineIdx="{mediaLineIdx}"')

p_mediaHalfAlreadyExists = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipSdpManipulator.cpp({line:d})" Method="SipSdpManipulator::allocateMediaHalfIfRequired" Thread="{thread:S}":  this="{this:S}" Media half already exists mediaLineIdx="{mediaLineIdx}"')

p_mediaHalfAllocationSuccess = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipSdpManipulator.cpp({line:d})" Method="SipSdpManipulator::mediaHalfAllocationSuccess" Thread="{thread:S}":  this="{this:S}" Media half allocation success called')

p_sdpMediaManipulatorDestructor2 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/{manipulatorType}SipSdpManipulator.cpp({line:d})" Method="{manipulatorType}SipSdpManipulator::~{manipulatorType}SipSdpManipulator" Thread="{thread:S}":  this="{this:S}" Destructor')

p_releaseMediaHalf = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipSdpManipulator.hpp({line:d})" Method="SipSdpManipulator::releaseMediaHalfT" Thread="{thread:S}":  this="{this:S}" Releasing media half for mediaLineIdx={mediaLineIdx}')

p_sdpMediaManipulatorDestructor = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="developer.sip.leg" Level="DEBUG" CodeLocation="ppcmains/sip/sipproxy/SipSdpManipulator.cpp({line:d})" Method="SipSdpManipulator::~SipSdpManipulator" Thread="{thread:S}":  this="{this:S}" Destructor')

# Media Session Manager
p_getMediaHalf = compile('2017-12-30T11:52:34.026-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2017-12-30 16:52:34,022" Module="developer.mediasessionmgr" Level="DEBUG" CodeLocation="ppcmains/oak/mediasession/MediaSessionMgr.cpp(311)" Method="MediaSessionMgr::getAssentDemuxServerMediaHalf" Thread="0x7fc1d8e2d700": MFF = 0x556a70b542c0, handler addr = 0x556a755b2278, Cookie = 0, CallSerialNumber = a162a9ed-4a56-43be-8599-1ae67d024cbf, sessionKey = branchId = 1, streamtype = STREAM_TYPE_AUDIO, streamNum = 1, sessionSideId = 0, ipnet = \'IPv4\' m_remoteAddress: [\'IPv4\'\'TCP\'\'10.81.54.102:25017\'] (best local: 10.81.54.5 -> remote: 10.81.54.102)')


def parse_isMediaRouted(line, currentProxyLegThis):
    r = p_isMediaRouted.search(line)
    if r is None:
        return False, currentProxyLegThis
    else:
        this = getThisPointer(r['this'])
        proxyLeg = gProxyLegMap.get(this)
        if proxyLeg is None:
            # We should have already created the proxy leg, this is the third log expected after SetNextHop
            print this + " parse_outboundSetNextHop : *** Expected to find a proxy leg entry but didn't"
            print line
        return True, this

def parse_mediaManipulatorCreateInstance(line, currentProxyLegThis):
    # This is where we get the manipulator type. We need the current proxy leg pointer because this log
    # doesn't have that reference

    # No need to parse this if we don't have the proxy pointer
    if currentProxyLegThis is None:
        return False

    r = p_mediaManipulatorCreateInstance.search(line)
    if r is None:
        return False
    else:
        proxyLeg = gProxyLegMap.get(currentProxyLegThis)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print currentProxyLegThis + " parse_mediaManipulatorCreateInstance : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            gProxyLegMap[currentProxyLegThis] = proxyLeg
        return True


def parse_sdpMediaManipulatorConstructor(line, currentProxyLegThis):
    # This is where we get the 'this' pointer for the manipulator to use in all future manipulator logs.  We need the
    # current proxy leg pointer because this log doesn't have that reference
    global gLogList, gNumTries, gManipulatorMap

    # No need to parse this if we don't have the proxy pointer
    if currentProxyLegThis is None:
        return False, currentProxyLegThis

    r = p_sdpMediaManipulatorConstructor2.parse(line)
    if r is None:
        # Should match the manipulator within 5 logs of the isMediaRouted log
        gNumTries += 1
        if gNumTries > 5:
            currentProxyLegThis = None
            gNumTries = 0
        return False, currentProxyLegThis
    else:
        proxyLeg = gProxyLegMap.get(currentProxyLegThis)
        if proxyLeg is None:
            # We should have already created the proxy leg
            print currentProxyLegThis + " parse_sdpMediaManipulatorConstructor : *** Expected to find a proxy leg entry but didn't"
            print line
        else:
            proxyLeg.mediaManipulatorThis = r['this']
            proxyLeg.mediaManipulatorType.append(r['manipulatorType'])
            gProxyLegMap[currentProxyLegThis] = proxyLeg
            gLogList.append(Log(currentProxyLegThis, r['timestamp2'], 'Construct ' + r['manipulatorType'], 'Construct ' + r['manipulatorType']))
            gManipulatorMap[r['this']] = currentProxyLegThis
        return True, currentProxyLegThis


def parse_sdpMediaManipulatorDestructor(line):
    global gLogList, gManipulatorMap
    r = p_sdpMediaManipulatorDestructor2.parse(line)
    if r is None:
        return False
    else:
        manipulatorThis = r['this']
        proxyLegThis = gManipulatorMap.get(manipulatorThis)
        if proxyLegThis is None:
            print manipulatorThis + " parse_sdpMediaManipulatorDestructor : *** Expected to find manipulatorThis in the gManipulatorMap, but didn't"
        else:
            gLogList.append(Log(proxyLegThis, r['timestamp2'], 'Destruct ' + r['manipulatorType'], 'Destruct ' + r['manipulatorType']))
            #gManipulatorMap[manipulatorThis] = None
        return True


def parse_mediaHalfRequested(line):
    global gLogList, gManipulatorMap
    r = p_mediaHalfRequested.parse(line)
    if r is None:
        return False
    else:
        manipulatorThis = r['this']
        proxyLegThis = gManipulatorMap.get(manipulatorThis)
        if proxyLegThis is None:
            print manipulatorThis + " parse_mediaHalfRequested : *** Expected to find manipulatorThis in the gManipulatorMap, but didn't"
        else:
            gLogList.append(Log(proxyLegThis, r['timestamp2'], 'Media half requested idx ' + r['mediaLineIdx'], 'Media half requested idx ' + r['mediaLineIdx']))
        return True


def parse_releaseMediaHalf(line):
    global gLogList, gManipulatorMap
    r = p_releaseMediaHalf.parse(line)
    if r is None:
        return False
    else:
        manipulatorThis = r['this']
        proxyLegThis = gManipulatorMap.get(manipulatorThis)
        if proxyLegThis is None:
            print manipulatorThis + " parse_releaseMediaHalf : *** Expected to find manipulatorThis in the gManipulatorMap, but didn't"
            print line
        else:
            gLogList.append(Log(proxyLegThis, r['timestamp2'], 'Media half released idx ' + r['mediaLineIdx'], 'Media half released idx ' + r['mediaLineIdx']))
        return True


def parse_mediaHalfAllocationSuccess():
    return False


def parse_mediaHalfAlreadyExists():
    return False



# ====================================================================================================================
#                                        N E T W O R K   S I P   L O G S
# ====================================================================================================================

# 2018-01-01T12:56:48.964-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2018-01-01 17:56:48,964" Module="network.sip" Level="INFO":  Action="Received" Local-ip="10.81.54.5" Local-port="5061" Src-ip="10.122.73.183" Src-port="47177" Detail="Receive Request Method=INVITE, CSeq=100, Request-URI=sip:1004@vm-bluck-fed-cust2-cucm1.cisco.com, Call-ID=e7e75ff9a67fb2435b25eab2a1498171, From-Tag=809f1f10ebdb302c, To-Tag=, Msg-Hash=14340233468942773735, Local-SessionID=, Remote-SessionID="

# 2018-01-01T12:56:43.846-05:00 vm-bluck-fed-vcse1 tvcs: UTCTime="2018-01-01 17:56:43,846" Module="network.sip" Level="INFO":  Action="Sent" Local-ip="10.81.54.5" Local-port="7012" Dst-ip="10.81.54.102" Dst-port="25018" Detail="Sending Response Code=200, Method=OPTIONS, CSeq=30235, To=sip:10.81.54.5:7012, Call-ID=3be07e0ceb19d6df@10.81.54.102, From-Tag=c924fa30c7e5bdb2, To-Tag=00257b9a244d2547, Msg-Hash=9783133151195055080, Local-SessionID=, Remote-SessionID="

p_networkSipReceivedReq = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="INFO":  Action="Received" Local-ip="{localIP:S}" Local-port="{localPort:S}" Src-ip="{srcIP:S}" Src-port="{srcPort:S}" Detail="Receive Request Method={method:w}, CSeq={cseq:S}, Request-URI={reqUri:S}, Call-ID={callid:S}, From-Tag{fromtag:S}, To-Tag{totag:S}, Msg-Hash{msghash:S}, Local-SessionID{localsessid:S}, Remote-SessionID{remsessid:S}"')

# 2018-01-18T11:34:39.499-06:00 rcdn6-vm67-40 tvcs: UTCTime="2018-01-18 17:34:39,499" Module="network.sip" Level="INFO":  Action="Received" Local-ip="10.89.67.40" Local-port="5061" Src-ip="10.89.106.35" Src-port="50209" Detail="Receive Request Method=REGISTER, CSeq=1176, To=sip:7022@rcdn6-vm118-41.cisco.com, Call-ID=00ebd5d5-d8c60008-3d372b84-5f6b0fd9@10.89.106.35, From-Tag=00ebd5d5d8c6035e6dbee882-304060fa, To-Tag=, Msg-Hash=17912736280473840983"

p_networkSipReceivedReq2 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="INFO":  Action="Received" Local-ip="{localIP}" Local-port="{localPort}" Src-ip="{srcIP}" Src-port="{srcPort}" Detail="Receive Request Method={method:w}, CSeq={cseq:S}, To={reqUri:S}, Call-ID={callid:S}, From-Tag{fromtag}, To-Tag{totag}, Msg-Hash{msghash}"')

p_networkSipReceivedResp = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="INFO":  Action="Received" Local-ip="{localIP:S}" Local-port="{localPort:S}" Src-ip="{srcIP:S}" Src-port="{srcPort:S}" Detail="Receive Response Code={respCode:S}, Method={method:w}, CSeq={cseq:S}, To={to:S}, Call-ID={callid:S}, From-Tag{fromtag:S}, To-Tag{totag:S}, Msg-Hash{msghash:S}, Local-SessionID{localsessionid:S}, Remote-SessionID{remotesessionid:S}"')

p_networkSipReceivedDebug = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {app:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="DEBUG":  Action="Received" Local-ip="{localIP:S}" Local-port="{localPort:S}" Src-ip="{srcIP:S}" Src-port="{srcPort:S}" Msg-Hash="{msgHash:S}"')

p_networkSipSentReq = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="INFO":  Action="Sent" Local-ip="{localIP:S}" Local-port="{localPort:S}" Dst-ip="{destIP:S}" Dst-port="{destPort:S}" Detail="Sending Request Method={method:w}, CSeq={cseq:S}, Request-URI={requri:S}, Call-ID={callid:S}, From-Tag{fromtag:S}, To-Tag{totag:S}, Msg-Hash{msghash:S}, Local-SessionID{localsessid:S}, Remote-SessionID{remsessid:S}"')

# 2018-01-18T12:34:33.318-05:00 rcdn6-vm67-42 tvcs: UTCTime="2018-01-18 17:34:33,319" Module="network.sip" Level="INFO":  Action="Sent" Local-ip="10.89.67.42" Local-port="25033" Dst-ip="10.89.118.41" Dst-port="5061" Detail="Sending Request Method=REGISTER, CSeq=1177, To=sip:9022@rcdn6-vm118-41.cisco.com, Call-ID=00ccfc99-dfc1000b-097eed33-7284631f@10.89.106.39, From-Tag=00ccfc99dfc1035f22eb415e-4a3518a3, To-Tag=, Msg-Hash=14400613170240473984"

p_networkSipSentReq2 = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="INFO":  Action="Sent" Local-ip="{localIP:S}" Local-port="{localPort:S}" Dst-ip="{destIP:S}" Dst-port="{destPort:S}" Detail="Sending Request Method={method:w}, CSeq={cseq:S}, To={requri:S}, Call-ID={callid:S}, From-Tag{fromtag:S}, To-Tag{totag:S}, Msg-Hash{msghash:S}"')

p_networkSipSentResp = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} tvcs: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="INFO":  Action="Sent" Local-ip="{localIP:S}" Local-port="{localPort:S}" Dst-ip="{destIP:S}" Dst-port="{destPort:S}" Detail="Sending Response Code={respCode:S}, Method={method:w}, CSeq={cseq:S}, To={to:S}, Call-ID={callid:S}, From-Tag{fromtag:S}, To-Tag{totag:S}, Msg-Hash{msghash:S}, Local-SessionID{localsessid:S}, Remote-SessionID{remsessid:S}"')

p_networkSipSentDebug = compile('{date:S}T{timestamp:S}-0{tz:d}:00 {hostname:S} {app:S}: UTCTime="{date2:S} {timestamp2:S}" Module="network.sip" Level="DEBUG":  Action="Sent" Local-ip="{localIP:S}" Local-port="{localPort:S}" Dst-ip="{destIP:S}" Dst-port="{destPort:S}" Msg-Hash="{msgHash:S}"')

p_from = compile('From: <sip:{fromuri:S}>;tag={fromtag:S}')
p_cline = compile('c=IN IP4 {cip:S}')
p_mline = compile('m={media:w} {port:d} {mediatype:S}')
p_rtcp = compile('a=rtcp:{port:d}')
p_remotecandidates = compile('a=remote-candidates:{comp1:d} {remoteIP1:S} {remotePort1:d} {comp2:d} {remoteIP2:S} {remotePort2:d}')


def parse_networkSipDebug(line, f):
    global gLogList, gPortAssignment, gB2buaPortAssignment,  gCurrLinenum, gCallIDMap, gCucmIP, gPhone1IP, gExpEIP, gCallIDtoSessionID, gCallIDtoRemoteSessionID

    direction = 'sent'
    r = p_networkSipReceivedDebug.parse(line)
    if r is not None:
        direction = 'rcvd'
        remoteIP = r['srcIP']
        localIP = r['localIP']
        logId = remoteIP
    else:
        r = p_networkSipSentDebug.parse(line)
        if r is not None:
            remoteIP = r['destIP']
            localIP = r['localIP']
            logId = remoteIP
        else:
            return False

    appIsB2bua = False
    if 'b2bua' in r['app']:
        appIsB2bua = True

    # The text following this log is the contents of the sip msg. Search the sip message for useful info.
    # Save the data to the log file. The IP address is the endpoint where the message was sent to or received
    # from. It will be examined when outputing the flow to put it in the right column.

    timestamp = r['timestamp2']
    cip = '0.0.0.0'
    totag = False
    isRequest = False
    reqUri = ''
    contact = ''
    callid = None
    smallCallId = ''
    fromCUCM = None
    fromB2BUA = None
    fromProxy = None
    srcEntity = None
    viaIsCucm = False
    routeIsCucm = False
    msgType = 'Unknown'
    callFlowLocation = '????'
    msgTypeTimestamp = getTimestamp(timestamp)
    msgTypeLinenum = gCurrLinenum
    for line in f:
        gCurrLinenum += 1
        line = line.strip()
        # Look for the end of the sip msg
        if line.endswith('|'):
            # Done with processing the message
            break
        if line.startswith('|'):
            # First line of the message contains the req method or resp code
            if line.endswith('SIP/2.0'):
                # Req method
                lineParts = line.split()
                msgType = lineParts[0].strip('|')
                reqUri = lineParts[1]
                isRequest = True
            else:
                # Resp code
                msgType = " ".join(line.split()[1:3])
                isRequest = False
                #if msgType.startswith("100"):
                    # Ignore 100 Trying, doesn't add anything to the troubleshooting
                #    return True

        if msgType.startswith('OPTIONS'):
            # don't waste our time with OPTIONS
            return True

        # Responses don't have Route header so need to use Via. If Via contains a CUCM zone and its a response, then
        # the message is heading towards the CUCM (because Via is used to route the message)
        if line.startswith("Via:"):
            if "CEtcp" in line or "CEtls" in line:
                viaIsCucm = True

        # Check if its a To: header and if so, whether it has a tag. We don't care what the tag is, just whether it
        # has one. If no tag, this is the first INVITE and we can deduce which direction its traveling. If it does
        # have a tag then we'll need to use the recorded From tag to deduce the direction. This direction is used
        # to determine where the ports need to appear in the call flow diagram.
        if line.startswith("To:"):
            if "tag" in line:
                totag = True

        # Call-ID
        if line.startswith("Call-ID:"):
            callid = line.split()[1]
            smallCallId = callid.split('@')[0][-3:]

        # Session-ID: 1ddc2c5200105000a00000ccfc99dfc1;remote=00000000000000000000000000000000
        if line.startswith("Session-ID:"):
            sessionId = line.split()[1].split(';')[0]
            remoteSessionId = line.split('=')[1]
            if isRequest and gCallIDtoSessionID.get(callid) is None:
                # Get session ID in the request direction
                gCallIDtoSessionID[callid] = sessionId
            if not isRequest and gCallIDtoRemoteSessionID.get(callid) is None and sessionId != '00000000000000000000000000000000':
                # Get the session ID in the response direction once allocated; e.g., 100 Trying does not allocate it so will be all zeros
                gCallIDtoRemoteSessionID[callid] = sessionId



        # Add CSeq info to the message type (e.g. 100 Trying (CSeq 101))
        if line.startswith("CSeq:"):
            cseq = line.split()[1]
            msgType += " (CSeq:%s CallID:%s)" % (cseq, smallCallId)
            #msgType += " (CSeq " + line.split()[1] + ")"

        # Look for Call-Info headers to see if this is a HOLD or RESUME message
        if line == " Call-Info: <urn:x-cisco-remotecc:hold>":
            operation = "  *** HOLD ***"
            gLogList.append(Log(logId, timestamp, operation, line))
            continue
        if line == " Call-Info: <urn:x-cisco-remotecc:resume>":
            operation = "  *** RESUME ***"
            gLogList.append(Log(logId, timestamp, operation, line))
            continue

        # Check if its a Route header and if so, whether it contains CEtcp or CEtls, either of which indicate the
        # message is a request and is heading twoards the CUCM.
        if line.startswith("Route:"):
            if "CEtcp" in line or "CEtls" in line:
                routeIsCucm = True

        # See if this message is from CUCM
        if line.startswith("Server:") or line.startswith("User-Agent:"):
            if 'Cisco-CUCM' in line:
                fromCUCM = True
            elif 'b2bua' in line:
                fromB2BUA = True
            elif 'TANDBERG' in line:
                fromProxy = True

        # Grab the IP address in the Contact header. We can use this to identify the first phone using the first
        # INVITE received
        if line.startswith("Contact:"):
            contact = line
            if gPhone1IP is None and 'INVITE' in msgType:
                gPhone1IP = line.split('@')[1].split(':')[0]

        # Check if we're done processing headers
        if line.startswith('Content-Length'):
            # Finished with headers so now we can figure out where we are in the call flow.
            if appIsB2bua:
                # This is a b2bua log.
                callFlowLocation = calculateB2buaCallFlowLocation(callFlowLocation, callid, direction, fromCUCM, isRequest,
                                                                  msgType, msgTypeLinenum, msgTypeTimestamp, reqUri,
                                                                  routeIsCucm, totag, viaIsCucm)
                # If we successfully identified the b2bua call flow location (e.g. 'b2bua1in') update our logId which
                # starts out with just the IP address of the entity.
                if 'b2bua' in callFlowLocation:
                    logId = callFlowLocation

            elif remoteIP == gCucmIP:
                # This is a proxy log to or from CUCM. Check if we're sending to or receiving from CUCM or the Expressway-E
                # Now we determine whether this is on the left side of the CUCM (cucmIn) or the right side of the
                # CUCM (cucmOut). We can do this using the CallID because, unlike B2BUA, CUCM uses a diffferent
                # CallID for each call leg. If the message traversed the B2BUA, we've already updated the callid
                # map, but if not, we need to update it. INVITEs traverse the B2BUA but REGISTERs and SUBSCRIBEs
                # do not.
                if gCallIDMap.get(callid) is None:
                    # Hasn't hit the b2bua yet so CUCM is initiating this CallID. See if this is out-of-dialog
                    if not totag and isRequest and direction is 'rcvd':
                        # CUCM is sending the message, let's see which phone IP its sending to
                        if gPhone1IP is not None and gPhone1IP in reqUri:
                            gCallIDMap[callid] = 'cucmIn'
                            logId = 'cucmIn'
                        else:
                            gCallIDMap[callid] = 'cucmOut'
                            logId = 'cucmOut'
                elif gCallIDMap[callid] is 'b2bua1' or gCallIDMap[callid] is 'cucmIn' or gCallIDMap[callid] is 'proxy0':
                    # The callid is on the left of CUCM
                    logId = 'cucmIn'
                else:
                    # The callid is on the right of CUCM
                    logId = 'cucmOut'

            elif localIP == gExpEIP:
                # This is a proxy log on the Exp-E. We first need to figure out if its proxy0 or proxy5.
                # Since the whole callflow is built relative to the first INVITE flowing left to right, we can't
                # make any decisions until we get that first INVITE
                if gCallIDMap.get(callid) is None:
                    # We're processing the Exp-E log file so the callid map hasn't been built by the CUCM and
                    # B2BUA logic above, which happens when processing the Exp-C log file.
                    if gPhone1IP is None:
                        # Can't make any assumptions yet, need to wait for the first INVITE.
                        continue
                    elif isRequest and direction is 'rcvd':
                        if not fromCUCM and not fromB2BUA:
                            # must be from the phone, but which one? look in the Contact header
                            if gPhone1IP in contact:
                                gCallIDMap[callid] = 'proxy0'
                            else:
                                gCallIDMap[callid] = 'proxy5'
                        else:
                            # must be from CUCM or B2BUA heading to the phone, look in the reqURI
                            if gPhone1IP in reqUri:
                                gCallIDMap[callid] = 'proxy0'
                            else:
                                gCallIDMap[callid] = 'proxy5'
                if direction is 'rcvd':
                    if gCallIDMap.get(callid) is 'proxy0':
                        if fromProxy:
                            # Must be from proxy1 on the Exp-C (e.g. 100 Trying which is point-to-point, not UA-to-UA)
                            logId = 'proxy0out'
                            srcEntity = 'Proxy1'
                        elif not fromCUCM and not fromB2BUA:
                            # Must be from the phone
                            # logId = 'proxy0in'

                            # Instead of recording this relative to the proxy, we're going to record it with the phone
                            # IP because that allows multiple different phones to be shown in the call flow (e.g. transfer case).
                            # Note that the logId is initialized with the remoteIP above but setting it here explicitly to make it clear
                            # why were using the phone IP.
                            logId = remoteIP
                        else:
                            # From either CUCM or the B2BUA. Some messages don't go though B2BUA
                            logId = 'proxy0out'
                            srcEntity = 'Proxy2' if fromCUCM else 'Proxy1'
                    elif gCallIDMap.get(callid) is 'proxy5':
                        if fromProxy:
                            # Must be from proxy4 on the Exp-C (e.g. 100 Trying which is point-to-point, not UA-to-UA)
                            logId = 'proxy5in'
                            srcEntity = 'Proxy4'
                        elif not fromCUCM and not fromB2BUA:
                            # Must be from the phone
                            # logId = 'proxy5out'

                            # Instead of recording this relative to the proxy, we're going to record it with the phone
                            # IP because that allows multiple different phones to be shown in the call flow (e.g. transfer case).
                            # Note that the logId is initialized with the remoteIP above but setting it here explicitly to make it clear
                            # why were using the phone IP.
                            logId = remoteIP
                        else:
                            # From either CUCM or B2BUA
                            logId = 'proxy5in'
                            srcEntity = 'Proxy3' if fromCUCM else 'Proxy4'
                elif direction is 'sent':
                    if gCallIDMap.get(callid) is 'proxy0':
                        if remoteIP == gExpCIP:
                            logId = 'proxy0out'
                        else:
                            #logId = 'proxy0in'
                            logId = remoteIP
                    elif gCallIDMap.get(callid) is 'proxy5':
                        if remoteIP == gExpCIP:
                            logId = 'proxy5in'
                        else:
                            #logId = 'proxy5out'
                            logId = remoteIP
                continue


        if line == " a=inactive" or line == " a=sendonly" or line == " a=recvonly":
            operation = ' ' + line
            gLogList.append(Log(logId, timestamp, operation, line))
            continue
        if ";apparent" in line:
            # gLogList.append(Log(logId, timestamp, line[0:7] + ' has apparent', line))
            continue
        # r = p_cline.search(line)
        # if r is not None:
        #     # This is the IP address where the media is coming from (as opposed to the signaling)
        #     cip = r['cip']
        #     continue
        r = p_mline.search(line)
        if r is not None:
            # Remember that this port was assigned to the endpoint. We'll use this when we have routing
            # connections from 'undef' and need to figure out which side of the call flow they go on.
            port = str(r['port'])
            gPortAssignment[port] = remoteIP

            # This is the internal port assignment. Only assign the port the first time, that should be where the port
            # was allocated and sent in SDP. Subsequent appearances could be where it is received
            if 'b2bua' in callFlowLocation:
                gB2buaPortAssignment[port] = callFlowLocation

            mline = '  m=%s %s %s' % (r['media'], port, r['mediatype'])
            gLogList.append(Log(logId, timestamp, mline, line))

            continue
        r = p_rtcp.search(line)
        if r is not None:
            # Same as above but for the rtcp port
            port = str(r['port'])
            gPortAssignment[port] = remoteIP
            if 'b2bua' in callFlowLocation:
                gB2buaPortAssignment[port] = callFlowLocation
            # Go ahead and include the whole line (with helpful indent), its not long
            aline = '   ' + line
            gLogList.append(Log(logId, timestamp, aline, line))
            continue
        r = p_remotecandidates.search(line)
        if r is not None:
            aline = '   a=remote-candidates:'
            gLogList.append(Log(logId, timestamp, aline, line))
            aline = '    ' + str(r['comp1']) + ' ' + r['remoteIP1'] + ':' + str(r['remotePort1'])
            gLogList.append(Log(logId, timestamp, aline, line))
            aline = '    ' + str(r['comp2']) + ' ' + r['remoteIP2'] + ':' + str(r['remotePort2'])
            gLogList.append(Log(logId, timestamp, aline, line))
            continue

    # Add the req method or resp code that we saved above. Do this here so we have the updated logId so it gets
    # included in the right column in the output
    gLogList.append(Log(logId, '', msgType, line, direction, msgTypeTimestamp, msgTypeLinenum, srcEntity))

    return True


def calculateB2buaCallID(callFlowLocation, direction, routeIsCucm, callid):
    global gCallIDMap
    if direction is 'rcvd' and routeIsCucm:
        # This is the first B2BUA becaue it is the first INVITE being sent to CUCM
        callFlowLocation = 'b2bua1in'
        gCallIDMap[callid] = 'b2bua1'
    elif direction is 'rcvd' and not routeIsCucm:
        # This is the second B2BUA because it is the first INVITE and not heading for the CUCM
        callFlowLocation = 'b2bua2in'
        gCallIDMap[callid] = 'b2bua2'
    elif direction is 'sent' and routeIsCucm:
        # This is the first B2BUA becaue it is the first INVITE being sent to CUCM
        callFlowLocation = 'b2bua1out'
        gCallIDMap[callid] = 'b2bua1'
    elif direction is 'sent' and not routeIsCucm:
        # This is the second B2BUA because it is the first INVITE and not heading for the CUCM
        callFlowLocation = 'b2bua2out'
        gCallIDMap[callid] = 'b2bua2'
    return callFlowLocation

def calculateB2buaCallFlowLocation(callFlowLocation, callid, direction, fromCUCM, isRequest, msgType,
                                   msgTypeLinenum, msgTypeTimestamp, reqUri, routeIsCucm, totag, viaIsCucm):
    global gCallIDMap, gCucmIP, gLastReqSent

    # If there's no To tag and the message is a request, we know the message is traveling left to right in the call
    # flow so we use this assumption to build the gCallIDMap that we'll use for subsequent messages.
    if not totag and isRequest:
        callFlowLocation = calculateB2buaCallID(callFlowLocation, direction, routeIsCucm, callid)
    else:
        # The message either has a To tag or its a response without a To tag (e.g. 100 Trying to the
        # initial INVITE). Either way we should have the From tag in our map to learn which b2bua it is
        # (1 or 2) and then figure out whether its the 'in' side or 'out' side. 'In' is always the left
        # side of the b2bua in the flow, and 'out' is the right side.

        # If a To tag is present, this is not a dialog-initiating request so use the callID mapping we
        # created above when the dialog was initiated to figure out which b2bua we're on. From there we
        # can figure out which side of the b2bua.
        b2buaInstance = gCallIDMap.get(callid, '')

        if b2buaInstance is 'b2bua1' and direction is 'sent' and isRequest:
            if gCucmIP in reqUri:
                callFlowLocation = 'b2bua1out'
            else:
                callFlowLocation = 'b2bua1in'

        elif b2buaInstance is 'b2bua1' and direction is 'sent' and not isRequest:
            if viaIsCucm:
                callFlowLocation = 'b2bua1out'
            else:
                callFlowLocation = 'b2bua1in'

        elif b2buaInstance is 'b2bua1' and direction is 'rcvd' and '100 Trying' in msgType:
            # Handle 100 Trying which doesnt come from CUCM, it comes from the adjacent proxy
            if gLastReqSent is not None:
                callFlowLocation = gLastReqSent

        elif b2buaInstance is 'b2bua1' and direction is 'rcvd' and fromCUCM:
            callFlowLocation = 'b2bua1out'

        elif b2buaInstance is 'b2bua1' and direction is 'rcvd' and not fromCUCM:
            callFlowLocation = 'b2bua1in'



        elif b2buaInstance is 'b2bua2' and direction is 'sent' and isRequest:
            if gCucmIP in reqUri:
                callFlowLocation = 'b2bua2in'
            else:
                callFlowLocation = 'b2bua2out'

        elif b2buaInstance is 'b2bua2' and direction is 'sent' and not isRequest:
            if viaIsCucm:
                callFlowLocation = 'b2bua2in'
            else:
                callFlowLocation = 'b2bua2out'

        elif b2buaInstance is 'b2bua2' and direction is 'rcvd' and '100 Trying' in msgType:
            # Handle 100 Trying which doesnt come from CUCM, it comes from the adjacent proxy
            if gLastReqSent is not None:
                callFlowLocation = gLastReqSent

        elif b2buaInstance is 'b2bua2' and direction is 'rcvd' and fromCUCM:
            callFlowLocation = 'b2bua2in'

        elif b2buaInstance is 'b2bua2' and direction is 'rcvd' and not fromCUCM:
            callFlowLocation = 'b2bua2out'

        else:
            print "*** parse_networkSipDebug: Unknown b2buaInstance value: b2buaInstance '%s', callid '%s', msgType '%s' at %s on line %s" % (
            b2buaInstance, callid, msgType, msgTypeTimestamp, msgTypeLinenum)
            print gCallIDMap

    # Need this for 100 Trying received by b2bua
    if direction is 'sent' and isRequest:
        gLastReqSent = callFlowLocation
    return callFlowLocation


def parse_networkSipReceivedReq(line):
    global gLogList
    r = p_networkSipReceivedReq.parse(line)
    if r is None:
        r = p_networkSipReceivedReq2.parse(line)
        if r is None:
            return False
    # hijack the proxy leg this pointer field to store the phone IP address; we'll check for that when
    # printing the logs
    gLogList.append(Log(r['srcIP'], r['timestamp2'], r['method'] + ' (CSeq ' + r['cseq'] + ')', line, 'rcvd'))
    return True

def parse_networkSipReceivedResp(line):
    global gLogList
    r = p_networkSipReceivedResp.parse(line)
    if r is None:
        return False
    else:
        # hijack the proxy leg this pointer field to store the phone IP address; we'll check for that when
        # printing the logs
        gLogList.append(Log(r['srcIP'], r['timestamp2'], r['respCode'] + ' (CSeq ' + r['cseq'] + ')', line, 'rcvd'))
        return True

def parse_networkSipSentReq(line):
    global gLogList
    r = p_networkSipSentReq.parse(line)
    if r is None:
        r = p_networkSipSentReq2.parse(line)
        if r is None:
            return False
    # hijack the proxy leg this pointer field to store the phone IP address; we'll check for that when
    # printing the logs
    gLogList.append(Log(r['destIP'], r['timestamp2'], r['method'] + ' (CSeq ' + r['cseq'] + ')', line, 'sent'))
    return True

def parse_networkSipSentResp(line):
    global gLogList
    r = p_networkSipSentResp.parse(line)
    if r is None:
        return False
    else:
        # hijack the proxy leg this pointer field to store the phone IP address; we'll check for that when
        # printing the logs
        gLogList.append(Log(r['destIP'], r['timestamp2'], r['respCode'] + ' (CSeq ' + r['cseq'] + ')', line, 'sent'))
        return True




# ====================================================================================================================
#                                          F I L E   P R O C E S S I N G
# ====================================================================================================================

def parseFile(filename, routeMap, mediaThreadMap, packetRelayMap):
    global gNumTries, gCurrFilename, gCurrLinenum
    f = open(filename, "r")
    currentMsg = None
    currentSpecie = None
    currentIndividNum = None
    senderSpecie = None
    senderIndividNum = None
    currentProxyLegThis = None
    gNumTries = 0
    gCurrFilename = filename
    gCurrLinenum = 0

    print
    print "Processing %s" % filename
    start = datetime.datetime.now()
    for line in f:
        gCurrLinenum += 1

        # Make sure the line is a log line
        if line[0:4] != "2018":
            continue

        # Check for FSM logs
        match, currentSpecie, currentIndividNum, senderSpecie, senderIndividNum, currentMsg = \
            parse_startTask(line, currentSpecie, currentIndividNum, senderSpecie, senderIndividNum, currentMsg)
        if match:
            # print "=== executing %s on %s ===" % (currentMsg, currentSpecie, currentIndividNum)
            continue
        if parse_completeTask(line):
            # print "=== completed %s on %s ===" % (currentMsg, currentSpecie, currentIndividNum)
            currentSpecie = None
            currentIndividNum = None
            senderSpecie = None
            senderIndividNum = None
            currentProxyLegThis = None
            currentMsg = None
            continue

        # Check for SIP messages off the wire
        # if parse_networkSipReceivedReq(line):
        #     #print '  matched networkSipReceivedReq'
        #     continue
        # if parse_networkSipReceivedResp(line):
        #     #print '  matched networkSipReceivedResp'
        #     continue
        # if parse_networkSipSentReq(line):
        #     #print '  matched networkSipSentReq'
        #     continue
        # if parse_networkSipSentResp(line):
        #     #print '  matched networkSipSentResp'
        #     continue
        if parse_networkSipDebug(line, f):
            continue

        # Check for EPOLLIN logs to get the media threads
        if parse_epollin(line, mediaThreadMap):
            #print "  matched EPOLLIN"
            continue

        # Link up SIP proxy leg with the media manipulator
        match, currentProxyLegThis = parse_isMediaRouted(line, currentProxyLegThis)
        if match:
            # print "  matched isMediaRouted"
            continue
        match, currentProxyLegThis = parse_sdpMediaManipulatorConstructor(line, currentProxyLegThis)
        if match:
            # print "  matched sdpMediaManipulatorConstructor"
            continue
        if parse_sdpMediaManipulatorDestructor(line):
            #print "  matched sdpMediaManipulatorDestructor"
            continue
        if parse_mediaHalfRequested(line):
            #print "  matched sdpMediaManipulatorDestructor"
            continue
        if parse_releaseMediaHalf(line):
            #print "  matched sdpMediaManipulatorDestructor"
            continue

        # Check for network.mediarouting logs
        if parse_mediaRoutingCreateOutgoing(line, routeMap):
            continue
        if parse_mediaRoutingCreateIncoming(line, routeMap):
            continue
        if parse_mediaRoutingDeleteOutgoing(line, routeMap):
            continue
        if parse_mediaRoutingDeleteIncoming(line, routeMap):
            #print "  matched mediaRoutingDeleteUndefined"
            continue
        if parse_turnRoutingCreateOutgoing(line, routeMap):
            continue
        if parse_turnRoutingCreateIncoming(line, routeMap):
            continue
        if parse_turnRoutingDeleteOutgoing(line, routeMap):
            #print "  matched turnRouteDeleteOutgoing"
            continue
        if parse_turnRoutingDeleteIncoming(line, routeMap):
            #print "  matched turnRoutingDeleteIncoming"
            continue

        # Check for SipProxyLeg logs that appear outside of the message execution we care about
        if parse_destructor(line):
            #print "  matched destructor"
            continue
        if parse_DisplayResponseInfo(line):
            #print "  matched DisplayResponseInfo"
            continue
        if parse_processResponse(line):
            # print "  matched processResponse"
            continue
        if parse_SendStatefulResponseDirectly(line):
            #print "  matched DisplayResponseInfo"
            continue
        if parse_ReallySendSipRequest(line):
            #print "  matched ReallySendSipRequest"
            continue
        if parse_ProcessAckWithSdpRequest(line):
            #print "  matched ProcesAckWithSdpRequest"
            continue
        if parse_getRequiredLicensingType(line):
            print "  matched getRequiredLicensingType"
            continue

        # This was previously search only if currentMsg is SIPTrans_Ind but ran into a case where we saw this log
        #  without the SIPTrans_Ind execution before it.
        if parse_inboundNettleAndSrcIP(line):
            #print "  matched inboundNettleAndSrcIP"
            continue
        # Check for SipProxyLeg logs that appear when the message dispatcher is running
        #if currentMsg == "SIPTrans_Ind":
        if parse_ProcessInviteRequest(line):
            #print "  matched ProcessInviteRequest"
            continue
        if parse_apparent(line):
            #print "  matched apparent"
            continue

        # Check to see if we're in the middle of OUTBOUND message execution
        if currentMsg == "Run":
            if parse_outboundSendSipRequest(line, currentIndividNum):
                #print "  matched outboundSendSipRequest"
                continue
            if parse_outboundSetNextHop(line):
                #print "  matched outboundSetNextHop"
                continue
            if parse_outboundRouteViaNettle(line):
                #print "  matched outboundRouteViaNettle"
                continue
            continue

        # Check to see if we're in the middle of INBOUND message execution
        if currentMsg == "ProcessInviteRequest" or currentMsg == "ProcessNonInviteRequest":
            if parse_inboundProcessInitialRequest(line, currentIndividNum, currentMsg):
                #print "  matched inboundProcessInitialRequest"
                continue
        if currentMsg == "ProcessNonInviteRequest":
            if parse_ProcessSubsequentRequest(line):
                #print "  matched ProcessSubsequentRequest"
                continue

    f.close()
    parseMediaRelayInfo(filename, mediaThreadMap, packetRelayMap, start)

def parseMediaRelayInfo(filename, mediaThreadMap, packetRelayMap, start):
    # Now trace the file to get the media relay info by thread. The dict threadLogs will map each thread id we found
    # from the EPOLLIN logs to the list of log lines filtered by that thread id.
    threadLogs = {}
    for thread in mediaThreadMap.keys():
        logs = []
        f = open(filename, "r")
        for line in f:
            if thread in line:
                logs.append(line)
        threadLogs[thread] = logs

    # Now we have a list of log lines filtered for each thread id. threadLogs maps each thread id to the filtered log
    # lines with that thread id. We can use this to parase the media relay logs without interleaved logs between threads
    # getting in the way.
    for threadLog in threadLogs.values():
        logIter = iter(threadLog)
        for line in logIter:
            if parse_readDataAvailable(line, logIter, packetRelayMap):
                #print "  matched readDataAvailable"
                continue


    stop = datetime.datetime.now()
    delta = stop - start
    print
    print "Total time to process file %s seconds" % (delta.total_seconds())


def getProxyLegTable(proxyLegMap):
    proxyLegTable = PrettyTable(['This', 'Order', 'FSM', 'Direction', 'FromNettle', 'ToNettle', 'FromIP', 'ToIP',
                                 'OtherLeg', 'SipRequest', 'MediaManipulator', 'CallID', 'SessionID', 'Remote SessionID', 'Sublime Command'])
    proxyLegTable.align['Sublime Command'] = "l"  # left align column Sublime Command
    for proxyLeg in proxyLegMap.values():
        if proxyLeg.mediaManipulatorThis is not None:
            sublimeCommand = 'this="%s"|this="%s"|Self="SipProxyLegFsm:%s"' % (proxyLeg.this.split('-')[0],
                                                                               proxyLeg.mediaManipulatorThis,
                                                                               proxyLeg.individNum)
        else:
            sublimeCommand = 'this="%s"|Self="SipProxyLegFsm:%s"' % (proxyLeg.this.split('-')[0], proxyLeg.individNum)

        proxyLegTable.add_row([proxyLeg.this, proxyLeg.order, proxyLeg.individNum, proxyLeg.direction,
                               proxyLeg.fromNettle, proxyLeg.toNettle, proxyLeg.fromIP,
                               proxyLeg.toIP, proxyLeg.otherLeg, proxyLeg.sipRequest, proxyLeg.mediaManipulatorType,
                               proxyLeg.callID, proxyLeg.sessionID, proxyLeg.remoteSessionID, sublimeCommand])
    return proxyLegTable


def getRouteMapTable(routeMap):
    routeTable = PrettyTable(['Timestamp', 'Action', 'ExtIP1', 'ExtPort1', 'Socket 1', 'IP1', 'Port1', 'IP2', 'Port2', 'Socket 2', 'ExtIP2', 'ExtPort2'])
    for route in routeMap.values():
        seq = 1
        for event in route.event:
            timestamp = event.timestamp
            action = event.action
            if seq == 1:
                # Print all fields for the first 2 instances because the external ip addresses will have been updated
                routeTable.add_row([timestamp, action, event.extIP1, event.extPort1, route.socket1, route.ip1, route.port1, route.ip2,
                                    route.port2, route.socket2, event.extIP2, event.extPort2])
            else:
                routeTable.add_row([timestamp, action, event.extIP1, event.extPort1, '', '', '', '', '', '', event.extIP2, event.extPort2])
            seq += 1

    return routeTable


# def buildProxyListForExpE(proxyList):
#     global gOrigPhoneIP, gDestPhoneIP
#     for leg in gProxyLegMap.values():
#         otherLeg = gProxyLegMap.get(leg.otherLeg)
#         if otherLeg is None:
#             # Ignore proxy legs that don't have a mate
#             continue
#         if leg.isInvite and leg.direction == 'Inbound' and leg.fromIP == gOrigPhoneIP:
#             proxyList[0] = Proxy(0, leg.this, otherLeg.this,
#                                  leg.individNum, otherLeg.individNum,
#                                  leg.fromIP, otherLeg.toIP,
#                                  leg.fromNettle, otherLeg.toNettle)
#
#         if otherLeg.isInvite and otherLeg.direction == 'Outbound' and otherLeg.toIP == gDestPhoneIP:
#             proxyList[5] = Proxy(5, leg.this, otherLeg.this,
#                                  leg.individNum, otherLeg.individNum,
#                                  leg.fromIP, otherLeg.toIP,
#                                  leg.fromNettle, otherLeg.toNettle)

import operator
def buildProxyListForExpENoIP(callList, proxyLegMap):
    # This is the same as the method above except it tries to identify the proxies of interest without starting
    # with IP addresses. It does this by chosing the proxy legs by the order they were created. Thus, we need to
    # sort the dictionary by order
    firstInboundLeg = None
    firstOutboundLeg = None
    for leg in (sorted(proxyLegMap.values(), key=operator.attrgetter('order'))):
        otherLeg = proxyLegMap.get(leg.otherLeg)
        if otherLeg is None:
            # Ignore proxy legs that don't have a mate
            continue
        if leg.isInvite and leg.direction == 'Inbound':
            if firstInboundLeg is None:
                firstInboundLeg = leg
                firstOutboundLeg = otherLeg
            elif leg.sessionID + leg.remoteSessionID == firstInboundLeg.sessionID + firstInboundLeg.remoteSessionID:
                secondInboundLeg = leg
                secondOutboundLeg = otherLeg
                call = Call(leg.sessionID, leg.remoteSessionID)
                # Proxies are numerically indexed by the order they are created. Each proxy includes both inbound and outbound legs.
                call.proxyList[0] = Proxy(0, firstInboundLeg.this, firstOutboundLeg.this,
                                          firstInboundLeg.individNum, firstOutboundLeg.individNum,
                                          firstInboundLeg.fromIP, firstOutboundLeg.toIP,
                                          firstInboundLeg.fromNettle, firstOutboundLeg.toNettle)
                call.proxyList[5] = Proxy(5, secondInboundLeg.this, secondOutboundLeg.this,
                                          secondInboundLeg.individNum, secondOutboundLeg.individNum,
                                          secondInboundLeg.fromIP, secondOutboundLeg.toIP,
                                          secondInboundLeg.fromNettle, secondOutboundLeg.toNettle)
                callList.append(call)
                firstInboundLeg = None
                firstOutboundLeg = None
            else:
                print "*** : Second inbound leg doesn't have the same sessionID"



def buildProxyListForExpC(callList, proxyLegMap):
    global gExpEIP, gExpCIP, gCucmIP
    # Join the proxy legs and construct the sequence of proxies
    for call in callList:
        for inboundLeg in (sorted(proxyLegMap.values(), key=operator.attrgetter('order'))):
            # Is this leg part of the current call?
            if inboundLeg.session() == call.session():
                outboundLeg = proxyLegMap[inboundLeg.otherLeg]
                if inboundLeg.isInvite and inboundLeg.direction == 'Inbound' and inboundLeg.fromIP == gExpEIP:
                    call.proxyList[1] = Proxy(1, inboundLeg.this, outboundLeg.this,
                                              inboundLeg.individNum, outboundLeg.individNum,
                                              inboundLeg.fromIP, outboundLeg.toIP,
                                              inboundLeg.fromNettle, outboundLeg.toNettle)

                if inboundLeg.isInvite and inboundLeg.direction == 'Inbound' and inboundLeg.fromIP == gExpCIP and outboundLeg.toIP == gCucmIP:
                    call.proxyList[2] = Proxy(2, inboundLeg.this, outboundLeg.this,
                                              inboundLeg.individNum, outboundLeg.individNum,
                                              inboundLeg.fromIP, outboundLeg.toIP,
                                              inboundLeg.fromNettle, outboundLeg.toNettle)

                if inboundLeg.isInvite and inboundLeg.direction == 'Inbound' and inboundLeg.fromIP == gCucmIP:
                    call.proxyList[3] = Proxy(3, inboundLeg.this, outboundLeg.this,
                                              inboundLeg.individNum, outboundLeg.individNum,
                                              inboundLeg.fromIP, outboundLeg.toIP,
                                              inboundLeg.fromNettle, outboundLeg.toNettle)

                if inboundLeg.isInvite and inboundLeg.direction == 'Inbound' and inboundLeg.fromIP == gExpCIP and outboundLeg.toIP == gExpEIP:
                    call.proxyList[4] = Proxy(4, inboundLeg.this, outboundLeg.this,
                                              inboundLeg.individNum, outboundLeg.individNum,
                                              inboundLeg.fromIP, outboundLeg.toIP,
                                              inboundLeg.fromNettle, outboundLeg.toNettle)


def getProxyTable(proxyList):
    proxyTable = PrettyTable(['Num', 'InboundLeg (fsm)', 'OutboundLeg (fsm)', 'FromIP', 'ToIP', 'FromNettle', 'ToNettle'])
    for proxy in proxyList:
        if proxy is not None:
            proxyTable.add_row([proxy.num, proxy.inboundLeg + " (" + proxy.inboundFsm + ")",
                                proxy.outboundLeg + " (" + proxy.outboundFsm + ")",
                                proxy.fromIP, proxy.toIP, proxy.fromNettle, proxy.toNettle])

    return proxyTable


    
def getCallFlowTable(proxyList, routeMapE, routeMapC):
    global gCucmIP, gExpEIP
    global gLogList

    origPhoneIP = proxyList[0].fromIP
    destPhoneIP = proxyList[5].toIP
    phone1Entity = 'Phone1: ' + origPhoneIP
    phone2Entity = 'Phone2: ' + destPhoneIP
    msgTable = PrettyTable(
        ['Timestamp', phone1Entity, 'TURN1', 'ExpE Proxy0 In', 'ExpE Proxy0 Out', 'ExpC Proxy1 In', 'ExpC Proxy1 Out',
         'B2BUA1', 'ExpC Proxy2 In', 'ExpC Proxy2 Out', 'CUCM',
         'ExpC Proxy3 In', 'ExpC Proxy3 Out', 'B2BUA2', 'ExpC Proxy4 In', 'ExpC Proxy4 Out', 'ExpE Proxy5 In',
         'ExpE Proxy5 Out', 'TURN2', phone2Entity])
    msgTable.align[phone1Entity] = 'l'
    msgTable.align[phone2Entity] = 'l'
    msgTable.align['CUCM'] = 'l'
    msgTable.align['B2BUA1'] = 'l'
    msgTable.align['B2BUA2'] = 'l'

    # Get a raw list of list of strings, then add those as rows in the prettytable
    rows  = getCallFlowSIP(proxyList)
    rows += getCallFlowMediaE(proxyList, routeMapE)
    rows += getCallFlowMediaC(routeMapC)
    for row in rows:
        # Strip off first 2 items, filename and linenum. These don't apply to the ascii version of the table
        msgTable.add_row(row[2:])
    return msgTable


def getCallFlowSIP(proxyList):
    global gCucmIP, gExpEIP
    global gLogList
    asciiRows = []
    origPhoneIP = proxyList[0].fromIP
    destPhoneIP = proxyList[5].toIP
    for log in gLogList:
        # search for the phone IPs, CUCM IP, or the this pointer in our proxy list
        if log.this == origPhoneIP or log.this == 'proxy0in':
            msg = log.shortLog + {'rcvd': ' ->', 'sent': ' <-'}.get(log.direction, '')
            asciiRows.append([log.filename, log.linenum, log.timestamp, msg, '', '', '', '', '', '', '', '', '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == destPhoneIP or log.this == 'proxy5out':
            msg = {'rcvd': '<- ', 'sent': '-> '}.get(log.direction, '   ') + log.shortLog
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', '', '', '', '', '', '', msg])
        elif log.this == gCucmIP:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', log.shortLog,
                              '', '', '', '', '', '', '', '', ''])

        elif 'b2bua1in' in log.this:
            msg = {'rcvd': '-> ', 'sent': '<- '}.get(log.direction, '   ') + log.shortLog
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', msg, '', '', '',
                              '', '', '', '', '', '', '', '', ''])

        elif 'b2bua1out' in log.this:
            msg = log.shortLog + {'rcvd': ' <-', 'sent': ' ->'}.get(log.direction, '')
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', msg, '', '', '',
                              '', '', '', '', '', '', '', '', ''])

        elif 'b2bua1' is log.this:
            msg = log.shortLog
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', msg, '', '', '',
                              '', '', '', '', '', '', '', '', ''])

        elif 'b2bua2in' in log.this:
            msg = {'rcvd': '-> ', 'sent': '<- '}.get(log.direction, '   ') + log.shortLog
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', msg, '', '', '', '', '', ''])

        elif 'b2bua2out' in log.this:
            msg = log.shortLog + {'rcvd': ' <-', 'sent': ' ->'}.get(log.direction, '')
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', msg, '', '', '', '', '', ''])

        elif 'b2bua2' is log.this:
            msg = log.shortLog
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', msg, '', '', '', '', '', ''])

        elif log.this == proxyList[0].inboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', log.shortLog, '', '', '', '', '', '', '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[0].outboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', log.shortLog, '', '', '', '', '', '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[1].inboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', log.shortLog, '', '', '', '', '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[1].outboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', log.shortLog, '', '', '', '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[2].inboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', log.shortLog, '', '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[2].outboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', log.shortLog, '',
                              '', '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[3].inboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              log.shortLog, '', '', '', '', '', '', '', ''])
        elif log.this == proxyList[3].outboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', log.shortLog, '', '', '', '', '', '', ''])
        elif log.this == proxyList[4].inboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', '', log.shortLog, '', '', '', '', ''])
        elif log.this == proxyList[4].outboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', '', '', log.shortLog, '', '', '', ''])
        elif log.this == proxyList[5].inboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', '', '', '', log.shortLog, '', '', ''])
        elif log.this == proxyList[5].outboundLeg:
            asciiRows.append([log.filename, log.linenum, log.timestamp, '', '', '', '', '', '', '', '', '', '',
                              '', '', '', '', '', '', log.shortLog, '', ''])
    return asciiRows


def getCallFlowMediaE(proxyList, routeMapE):
    global gExpEIP, gPortAssignment
    asciiTable = []
    turnPort2ProxyIndexMap = {}
    origPhoneIP = proxyList[0].fromIP
    destPhoneIP = proxyList[5].toIP

    filterOn = False

    # Scan through our route map and record which phone the TURN allocations are for because when we encounter
    # a subsequent traversal connection to the 24000 range port, we'll know who its for. Otherwise there's no
    # clue in the route map entry itself, just the 24000 range port.
    for route in routeMapE.values():
        for event in route.event:
            if route.port1 == '3478' and event.extIP1 == origPhoneIP:
                # Connection between phone1 and TURN server
                turnPort2ProxyIndexMap[route.port2] = 'phone1'
            elif route.port1 == '3478' and event.extIP1 == destPhoneIP:
                # Connection between phone2 and TURN server
                turnPort2ProxyIndexMap[route.port2] = 'phone2'
    print
    print "turnPort2ProxyIndexMap"
    print turnPort2ProxyIndexMap
    print
    print "gPortAssignement"
    print gPortAssignment

    for route in routeMapE.values():
        for i in range(0, len(route.event)):
            event = route.event[i]
            extIP1 = event.extIP1
            extIP2 = event.extIP2
            if extIP1 == 'undef':
                # This is typical for incoming routes: the external source is undefined, or any source. But we need to
                # know which side of the call flow to put the info, so we check our port to IP mapping for a hint.
                extIP1 = gPortAssignment.get(route.port1)

            if proxyList[0].fromIP == extIP1 and proxyList[0].toIP == extIP2:
                # Connection between phone1 and exp-e (proxy 0)
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' -> '
                    symbol2 = '  X> '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' <- '
                    symbol2 = ' <X  '
                if filterOn and i+1 < len(route.event) and route.event[i+1].timestamp[0:len(timestamp)-1] == timestamp[0:len(timestamp)-1] and route.event[i+1].action == oppositeAction:
                    # This event is immediately cancelled by the next one so skip both. We only check events that have identical
                    # timestamps, otherwise we might miss significant events. We check the first 12 characters of the timestamp
                    # because we add an artificial 13th character to make the logs sequencial when sorting (see getTimestamp()).
                    i += 2
                    continue
                routestr0 = event.extPort1 + symbol1
                routestr1 = 'undef' + symbol1 if event.extPort1 == 'undef' else ''
                routestr2 = symbol1 + route.port1 + symbol2
                routestr3 = symbol2 + route.port2 + symbol1
                routestr4 = symbol1 + event.extPort2
                if 48000 <= int(event.extPort2) <= 59999:
                    # ports in the 48000-59999 range are allocated by the B2BUA so show the route in the B2BUA column
                    asciiTable.append([None, None, timestamp, routestr0, routestr1, routestr2, routestr3, symbol1, symbol1, routestr4, '', '', '',
                                      '', '', '', '', '', '', '', '', ''])
                else:
                    # otherwise ports are allocated by the proxy
                    asciiTable.append([None, None, timestamp, routestr0, routestr1, routestr2, routestr3, routestr4, '', '', '', '', '',
                                      '', '', '', '', '', '', '', '', ''])

            elif proxyList[5].toIP == extIP1 and proxyList[5].fromIP == extIP2:
                # Connection between phone2 and exp-e (proxy 5)
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <X  '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' -> '
                    symbol2 = '  X> '
                if filterOn and i+1 < len(route.event) and route.event[i+1].timestamp == timestamp and route.event[i+1].action == oppositeAction:
                    # This event is immediately cancelled by the next one so skip both. We only check events that have identical
                    # timestamps, otherwise we might miss significant events. We check the first 12 characters of the timestamp
                    # because we add an artificial 13th character to make the logs sequencial when sorting (see getTimestamp()).
                    i += 2
                    continue
                routestr0 = event.extPort2 + symbol1
                routestr1 = symbol1 + route.port2 + symbol2
                routestr2 = symbol2 + route.port1 + symbol1
                routestr3 = symbol1 + 'undef' if event.extPort1 == 'undef' else ''
                routestr4 = symbol1 + event.extPort1
                if 48000 <= int(event.extPort2) <= 59999:
                    # ports in the 48000-59999 range are allocated by the B2BUA so show the route in the B2BUA column
                    asciiTable.append([None, None, timestamp, '', '', '', '', '', '', '', '', '', '',
                                      '', '', routestr0, symbol1, symbol1, routestr1, routestr2, routestr3, routestr4])
                else:
                    # otherwise ports are allocated by the proxy
                    asciiTable.append([None, None, timestamp, '', '', '', '', '', '', '', '', '', '',
                                      '', '', '', '', routestr0, routestr1, routestr2, routestr3, routestr4])

            # Check for TURN connections
            elif route.port1 == '3478' and extIP1 == origPhoneIP:
                # Connection between phone1 and TURN server.
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' -> '
                    symbol2 = '  X> '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' <- '
                    symbol2 = ' <X  '
                if filterOn and i+1 < len(route.event) and route.event[i+1].timestamp[0:len(timestamp)-1] == timestamp[0:len(timestamp)-1] and route.event[i+1].action == oppositeAction:
                    # This event is immediately cancelled by the next one so skip both. We only check events that have identical
                    # timestamps, otherwise we might miss significant events. We check the first 12 characters of the timestamp
                    # because we add an artificial 13th character to make the logs sequencial when sorting (see getTimestamp()).
                    i += 2
                    continue
                routestr0 = event.extPort1 + symbol1
                routestr1 = symbol1 + route.port1 + symbol2 + route.port2 + symbol1
                routestr2 = symbol1 + event.extPort2
                asciiTable.append([None, None, timestamp, routestr0, routestr1, routestr2, '', '', '', '', '', '', '',
                                  '', '', '', '', '', '', '', '', ''])

            elif route.port1 == '3478' and extIP1 == destPhoneIP:
                # Connection between phone2 and TURN server
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <X  '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' -> '
                    symbol2 = '  X> '
                if filterOn and i+1 < len(route.event) and route.event[i+1].timestamp[0:len(timestamp)-1] == timestamp[0:len(timestamp)-1] and route.event[i+1].action == oppositeAction:
                    # This event is immediately cancelled by the next one so skip both. We only check events that have identical
                    # timestamps, otherwise we might miss significant events. We check the first 12 characters of the timestamp
                    # because we add an artificial 13th character to make the logs sequencial when sorting (see getTimestamp()).
                    i += 2
                    continue
                routestr0 = event.extPort2 + symbol1
                routestr1 = symbol1 + route.port2 + symbol2 + route.port1 + symbol1
                routestr2 = symbol1 + event.extPort1
                asciiTable.append([None, None, timestamp, '', '', '', '', '', '', '', '', '', '',
                                  '', '', '', '', '', '', routestr0, routestr1, routestr2])

            elif extIP1 == gExpEIP and 24000 <= int(event.extPort1) <= 29999 and turnPort2ProxyIndexMap.get(event.extPort1) == 'phone1':
                # This is a connection between exp-e traversal media stream and a TURN port allocated by phone1
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' -> '
                    symbol2 = '  X> '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' <- '
                    symbol2 = ' <X  '
                if filterOn and i+1 < len(route.event) and route.event[i+1].timestamp[0:len(timestamp)-1] == timestamp[0:len(timestamp)-1] and route.event[i+1].action == oppositeAction:
                    # This event is immediately cancelled by the next one so skip both. We only check events that have identical
                    # timestamps, otherwise we might miss significant events. We check the first 12 characters of the timestamp
                    # because we add an artificial 13th character to make the logs sequencial when sorting (see getTimestamp()).
                    i += 2
                    continue
                routestr0 = event.extPort1 + symbol1
                routestr1 = symbol1 + route.port1 + symbol2
                routestr2 = symbol2 + route.port2 + symbol1
                routestr3 = symbol1 + event.extPort2
                if 48000 <= int(event.extPort2) <= 59999:
                    # ports in the 48000-59999 range are allocated by the B2BUA so show the route in the B2BUA column
                    asciiTable.append([None, None, timestamp, '', routestr0, routestr1, routestr2, symbol1, symbol1, routestr3, '', '', '',
                                      '', '', '', '', '', '', '', '', ''])
                else:
                    # otherwise ports are allocated by the proxy
                    asciiTable.append([None, None, timestamp, '', routestr0, routestr1, routestr2, routestr3, '', '', '', '', '',
                                      '', '', '', '', '', '', '', '', ''])

            elif extIP1 == gExpEIP and 24000 <= int(event.extPort1) <= 29999 and turnPort2ProxyIndexMap.get(event.extPort1) == 'phone2':
                # This is a connection between exp-e traversal media stream and a TURN port allocated by phone2
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <X  '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' -> '
                    symbol2 = '  X> '
                if filterOn and i+1 < len(route.event) and route.event[i+1].timestamp[0:len(timestamp)-1] == timestamp[0:len(timestamp)-1] and route.event[i+1].action == oppositeAction:
                    # This event is immediately cancelled by the next one so skip both. We only check events that have identical
                    # timestamps, otherwise we might miss significant events. We check the first 12 characters of the timestamp
                    # because we add an artificial 13th character to make the logs sequencial when sorting (see getTimestamp()).
                    i += 2
                    continue
                routestr3 = symbol1 + event.extPort1
                routestr2 = symbol2 + route.port1 + symbol1
                routestr1 = symbol1 + route.port2 + symbol2
                routestr0 = event.extPort2 + symbol1
                if 48000 <= int(event.extPort2) <= 59999:
                    # ports in the 48000-59999 range are allocated by the B2BUA so show the route in the B2BUA column
                    asciiTable.append([None, None, timestamp, '', '', '', '', '', '', '', '', '', '',
                                      '', '', routestr0, symbol1, symbol1, routestr1, routestr2, routestr3, ''])
                else:
                    # otherwise ports are allocated by the proxy
                    asciiTable.append([None, None, timestamp, '', '', '', '', '', '', '', '', '', '', '', '', '', '', routestr0, routestr1, routestr2, routestr3, ''])
    return asciiTable


def filterMediaLog(i, route, timestamp, oppositeAction):
    # See if we're able to filter out the log
    if i + 1 >= len(route.event):
        return False
    if route.event[i + 1].action != oppositeAction:
        return False
    currTimestamp = revertTimestamp(timestamp)
    nextTimestamp =  revertTimestamp(route.event[i + 1].timestamp)
    timehalves = currTimestamp.split(',')
    # Will allow filtering if the next timestamp matches the current timestamp or 1 millisecond later
    nextmillisecond = str(int(timehalves[1]) + 1)
    maxTimestamp = ','.join([timehalves[0], nextmillisecond])
    if nextTimestamp == currTimestamp or nextTimestamp == maxTimestamp:
        return True
    return False


def getCallFlowMediaC(routeMapC):
    global gB2buaPortAssignment
    asciiTable = []

    print
    print "gB2buaPortAssignment"
    print gB2buaPortAssignment

    filterOn = True

    # This loop only handles B2BUA routes, still need code for the proxies on the C
    for route in routeMapC.values():
        internalPort1 = route.port1
        internalPort2 = route.port2
        i = 0
        while i < len(route.event):
            event = route.event[i]
            extIP1 = event.extIP1
            extIP2 = event.extIP2

            if gB2buaPortAssignment.get(internalPort1, '') is 'b2bua1in':
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <X- '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' -X> '
                if filterOn and filterMediaLog(i, route, timestamp, oppositeAction):
                    # This event is immediately cancelled by the next one so skip both
                    i += 2
                    continue
                routestr0 = event.extPort1 + symbol1
                routestr1 = symbol1 + route.port1
                routestr2 = symbol2 + route.port2 + symbol1
                routestr3 = symbol1 + event.extPort2
                asciiTable.append([None, None, timestamp, '', '', '', routestr0, symbol1, symbol1, routestr1 + routestr2, symbol1, symbol1, symbol1, symbol1, symbol1, routestr3, '', '', '', '', '', ''])

            elif gB2buaPortAssignment.get(internalPort1, '') is 'b2bua2in':
                action = event.action
                timestamp = event.timestamp
                symbol1 = ' ?? '
                symbol2 = ' ??? '
                oppositeAction = 'Undefined'
                # The following code does 2 things:
                #   1 - checking to see if we have 2 adjacent actions that cancel each other out.
                #       If so, we can eliminate them from the logs to reduce the clutter
                #   2 - set the arrow direction depending on whether its an incoming or outgoing action
                if action == 'Create Incoming':
                    oppositeAction = 'Delete Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <== '
                elif action == 'Create Outgoing':
                    oppositeAction = 'Delete Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' ==> '
                elif action == 'Delete Incoming':
                    oppositeAction = 'Create Incoming'
                    symbol1 = ' <- '
                    symbol2 = ' <X- '
                elif action == 'Delete Outgoing':
                    oppositeAction = 'Create Outgoing'
                    symbol1 = ' -> '
                    symbol2 = ' -X> '
                if filterOn and filterMediaLog(i, route, timestamp, oppositeAction):
                    # This event is immediately cancelled by the next one so skip both
                    i += 2
                    continue
                routestr0 = event.extPort1 + symbol1
                routestr1 = symbol1 + route.port1
                routestr2 = symbol2 + route.port2 + symbol1
                routestr3 = symbol1 + event.extPort2
                asciiTable.append([None, None, timestamp, '', '', '', '', '', '', routestr0, symbol1, symbol1, symbol1, symbol1, symbol1, routestr1 + routestr2, symbol1, symbol1, routestr3, '', '', ''])
            i += 1

    return asciiTable




def initialize(expeFilename, expcFilename, turnFilename):
    global gCurrentThisInstance
    global gFsmTable
    global gLogList
    global gProxyLegMap, gProxyLegMapE, gProxyLegMapC
    global gCallList
    global gManipulatorMap
    global gPacketRelayMapE, gPacketRelayMapC, gPacketRelayMapTurn
    global gExpEIP, gExpCIP, gCucmIP, gExpCInternalIP
    global gPortAssignment, gB2buaPortAssignment, gCallIDMap, gPhone1IP, gLastReqSent
    global gCallIDtoSessionID, gCallIDtoRemoteSessionID

    gPacketRelayMapE = {}
    gPacketRelayMapC = {}
    gPacketRelayMapTurn = {}
    gPortAssignment = {}
    gB2buaPortAssignment = {}
    gCallIDMap = {}
    gCallIDtoSessionID = {}
    gCallIDtoRemoteSessionID = {}
    gLastReqSent = None
    gPhone1IP = None
    routeMapE = {}
    routeMapC = {}
    routeMapTurn = {}
    mediaThreadMapE = {}
    mediaThreadMapC = {}
    mediaThreadMapTurn = {}

    # Table definitions
    gFsmTable = PrettyTable(['Timestamp', 'Source Specie', 'Source ID', 'Dest Specie', 'Dest ID', 'Msg', 'Next State'])

    # List of significant logs, ordered chronologically
    gLogList = []

    # Dictionary to keep track of the current instance of each this pointer. Indexed by native this pointer,
    # value is the current instance (starting with 1).
    gCurrentThisInstance = {}

    # Proxies are numerically indexed by the order they are created. Each proxy includes both inbound and outbound legs.
    gCallList = []

    verbose = False

    # ======== Process Exp E logs =========

    # Lists of proxy legs indexed by the 'this' pointer
    gProxyLegMap = {}
    gManipulatorMap = {}
    if expeFilename is not None:
        parseFile(expeFilename, routeMapE, mediaThreadMapE, gPacketRelayMapE)
        gProxyLegMapE = gProxyLegMap.copy()
        buildProxyListForExpENoIP(gCallList, gProxyLegMapE)
        if verbose:
            print
            print "PROXY E LEG TABLE"
            print "The Sublime Command is found at Edit > Line > Include lines with Regex"
            print "Be aware that 'this' pointers are reused, look for the 'Destructor' string to delineate uses."
            proxyLegTableE = getProxyLegTable(gProxyLegMapE)
            print proxyLegTableE.get_string(sortby="Order")
            print
            print "ROUTE TABLE E"
            routeTableE = getRouteMapTable(routeMapE)
            print routeTableE
            print
            print "MEDIA THREAD TABLE E"
            mtE = getMediaThreadTable(mediaThreadMapE)
            print mtE.get_string(sortby="Timestamp")
            print
            print "PACKET RELAY TABLE E"
            ptE = getPacketRelayTable(gPacketRelayMapE)
            print ptE.get_string(sortby="Timestamp")
            print "Size: " + str(len(gPacketRelayMapE))


    # ======== Process Exp C logs =========

    # Check if we have an internal IP address for Exp-C that we need to use when parsing the Exp-C file.
    if gExpCInternalIP is not None:
        gExpCIP = gExpCInternalIP

    if expcFilename is not None:
        gProxyLegMap.clear()
        gManipulatorMap.clear()
        parseFile(expcFilename, routeMapC, mediaThreadMapC, gPacketRelayMapC)
        gProxyLegMapC = gProxyLegMap.copy()
        if verbose:
            print
            print "PROXY C LEG TABLE"
            print "The Sublime Command is found at Edit > Line > Include lines with Regex"
            print "Be aware that 'this' pointers are reused, look for the 'Destructor' string to delineate uses."
            proxyLegTableC = getProxyLegTable(gProxyLegMapC)
            print proxyLegTableC.get_string(sortby="Order")
            print
            print "ROUTE TABLE C"
            routeTableC = getRouteMapTable(routeMapC)
            print routeTableC
            print
            print "MEDIA THREAD TABLE C"
            mtE = getMediaThreadTable(mediaThreadMapC)
            print mtE.get_string(sortby="Timestamp")
            print
            print "PACKET RELAY TABLE C"
            ptE = getPacketRelayTable(gPacketRelayMapC)
            print ptE.get_string(sortby="Timestamp")
            print "Size: " + str(len(gPacketRelayMapC))

        buildProxyListForExpC(gCallList, gProxyLegMapC)

    if turnFilename is not None:
        parseFile(turnFilename, routeMapTurn, mediaThreadMapTurn, gPacketRelayMapTurn)
        print
        print "ROUTE TABLE TURN"
        routeTableTurn = getRouteMapTable(routeMapTurn)
        print routeTableTurn

        # Combine TURN route map with E's so they all get included in the message flow
        routeMapE.update(routeMapTurn)
        print
        print "ROUTE TABLE COMBINED"
        routeTableCombined = getRouteMapTable(routeMapE)
        print routeTableCombined

        print
        print "MEDIA THREAD TABLE TURN"
        mtT = getMediaThreadTable(mediaThreadMapTurn)
        print mtT.get_string(sortby="Timestamp")
        print
        print "PACKET RELAY TABLE TURN"
        ptT = getPacketRelayTable(gPacketRelayMapTurn)
        print ptT.get_string(sortby="Timestamp")
        print "Size: " + str(len(gPacketRelayMapTurn))



    # ======== Common =========
    # if verbose:
        # print
        # print "FSM TABLE"
        # print gFsmTable
        # print SipProxyLegSet

    return gCallList[0].proxyList, routeMapE, routeMapC


# I'm using flask_table to render the message flow in html: https://github.com/plumdog/flask_table

class NonEscapedLinkCol(LinkCol):
    def td_contents(self, item, attr_list):
        # See if we have the file info to build a hyperlink
        if item.filename is None:
            # No, build a non-linked cell
            return Col.td_contents(self, item, attr_list)
        else:
            # Yes, build a linked cell
            return LinkCol.td_contents(self, item, attr_list)

    def td_format(self, content):
        # Selectively escape the contents because it has &nbsp; for proper indenting. Only need to escape <, not >
        return content.replace('<', '&lt')

class MsgFlowTable(Table):
    timestamp = NonEscapedLinkCol('Timestamp', '#',
                        attr='timestamp', anchor_attrs={'class': 'timestamp'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'left'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'timestamp'})
    phone1    = NonEscapedLinkCol('Phone1',  '#',
                        attr='phone1', anchor_attrs={'class': 'phone1'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'left'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'phone1'})
    turn1     = NonEscapedLinkCol('TURN1',  '#',
                        attr='turn1', anchor_attrs={'class': 'turn1'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'turn1'})
    proxy0in  = NonEscapedLinkCol('ExpE Proxy0 In',  '#',
                        attr='proxy0in', anchor_attrs={'class': 'proxy0in'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy0in'})
    proxy0out = NonEscapedLinkCol('ExpE Proxy0 Out',  '#',
                        attr='proxy0out', anchor_attrs={'class': 'proxy0out'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy0out'})
    proxy1in  = NonEscapedLinkCol('ExpC Proxy1 In',  '#',
                        attr='proxy1in', anchor_attrs={'class': 'proxy1in'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy1in'})
    proxy1out = NonEscapedLinkCol('ExpC Proxy1 Out',  '#',
                        attr='proxy1out', anchor_attrs={'class': 'proxy1out'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy1out'})
    b2bua1      = NonEscapedLinkCol('B2BUA1',  '#',
                        attr='b2bua1', anchor_attrs={'class': 'b2bua1'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'left'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'b2bua1'})
    proxy2in  = NonEscapedLinkCol('ExpC Proxy2 In',  '#',
                        attr='proxy2in', anchor_attrs={'class': 'proxy2in'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy2in'})
    proxy2out = NonEscapedLinkCol('ExpC Proxy2 Out',  '#',
                        attr='proxy2out', anchor_attrs={'class': 'proxy2out'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy2out'})
    cucm      = NonEscapedLinkCol('CUCM',  '#',
                        attr='cucm', anchor_attrs={'class': 'cucm'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'left'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'cucm'})
    proxy3in  = NonEscapedLinkCol('ExpC Proxy3 In',  '#',
                        attr='proxy3in', anchor_attrs={'class': 'proxy3in'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy3in'})
    proxy3out = NonEscapedLinkCol('ExpC Proxy3 Out',  '#',
                        attr='proxy3out', anchor_attrs={'class': 'proxy3out'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy3out'})
    b2bua2      = NonEscapedLinkCol('B2BUA2',  '#',
                        attr='b2bua2', anchor_attrs={'class': 'b2bua2'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'left'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'b2bua2'})
    proxy4in  = NonEscapedLinkCol('ExpC Proxy4 In',  '#',
                        attr='proxy4in', anchor_attrs={'class': 'proxy4in'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy4in'})
    proxy4out = NonEscapedLinkCol('ExpC Proxy4 Out',  '#',
                        attr='proxy4out', anchor_attrs={'class': 'proxy4out'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy4out'})
    proxy5in  = NonEscapedLinkCol('ExpE Proxy5 In',  '#',
                        attr='proxy5in', anchor_attrs={'class': 'proxy5in'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy5in'})
    proxy5out = NonEscapedLinkCol('ExpE Proxy5 Out',  '#',
                        attr='proxy5out', anchor_attrs={'class': 'proxy5out'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'proxy5out'})
    turn2     = NonEscapedLinkCol('TURN2',  '#',
                        attr='turn2', anchor_attrs={'class': 'turn2'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'center'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'turn2'})
    phone2    = NonEscapedLinkCol('Phone2',  '#',
                        attr='phone2', anchor_attrs={'class': 'phone2'}, url_kwargs=dict(filename='filename', linenum='linenum'),
                        column_html_attrs={'align': 'left'}, th_html_attrs={'bgcolor': 'lightgray'}, td_html_attrs={'class': 'phone2'})

class MsgFlowRow(object):
    def __init__(self, filename=None, linenum=None, timestamp='', phone1='', turn1='', proxy0in='', proxy0out='', proxy1in='', proxy1out='', b2bua1='', proxy2in='', proxy2out='',
                 cucm='', proxy3in='', proxy3out='', b2bua2='', proxy4in='', proxy4out='', proxy5in='', proxy5out='', turn2='', phone2=''):
        self.filename =   filename
        self.linenum =    linenum
        self.timestamp =  timestamp
        self.phone1 =     phone1
        self.turn1 =      turn1
        self.proxy0in =   proxy0in
        self.proxy0out =  proxy0out
        self.proxy1in =   proxy1in
        self.proxy1out =  proxy1out
        self.b2bua1 =     b2bua1
        self.proxy2in =   proxy2in
        self.proxy2out =  proxy2out
        self.cucm =       cucm
        self.proxy3in =   proxy3in
        self.proxy3out =  proxy3out
        self.b2bua2 =     b2bua2
        self.proxy4in =   proxy4in
        self.proxy4out =  proxy4out
        self.proxy5in =   proxy5in
        self.proxy5out =  proxy5out
        self.turn2 =      turn2
        self.phone2 =     phone2
        return



def getListOfMsgFlowRows(proxyList, routeMapE, routeMapC):
    # Get raw ascii rows
    ascii_rows  = getCallFlowSIP(proxyList)
    ascii_rows += getCallFlowMediaE(proxyList, routeMapE)
    ascii_rows += getCallFlowMediaC(routeMapC)

    # Convert to MsgFlowRows
    rows = []
    for ascii_row in ascii_rows:

        # To preserve any indentations when displayed on a browser
        for i, cell in enumerate(ascii_row):
            if type(cell) is str and cell.startswith(" "):
                ascii_row[i] = cell.replace(' ', '&nbsp;')

        rows.append( MsgFlowRow(filename   = ascii_row[0],
                                linenum    = ascii_row[1],
                                timestamp  = ascii_row[2],
                                phone1     = ascii_row[3],
                                turn1      = ascii_row[4],
                                proxy0in   = ascii_row[5],
                                proxy0out  = ascii_row[6],
                                proxy1in   = ascii_row[7],
                                proxy1out  = ascii_row[8],
                                b2bua1     = ascii_row[9],
                                proxy2in   = ascii_row[10],
                                proxy2out  = ascii_row[11],
                                cucm       = ascii_row[12],
                                proxy3in   = ascii_row[13],
                                proxy3out  = ascii_row[14],
                                b2bua2     = ascii_row[15],
                                proxy4in   = ascii_row[16],
                                proxy4out  = ascii_row[17],
                                proxy5in   = ascii_row[18],
                                proxy5out  = ascii_row[19],
                                turn2      = ascii_row[20],
                                phone2     = ascii_row[21]
                               ))
    sorted_rows = sorted(rows, key=lambda x: getattr(x, 'timestamp'))
    return sorted_rows


class SequenceDiagram(object):
    html = ''
    def __init__(self, entityList):
        SequenceDiagram.html += '''
    		<sequence-diagram-semantic>
                <header>
        '''
        for entity in entityList:
            SequenceDiagram.html += '<entity>' + entity + '</entity>\n'

            SequenceDiagram.html += '</header>\n'

    def action(cls, _from, to, text, filename, linenum):
        cls.html += '<action from="%s" to="%s"><a href="#%s#%s">%s</a></action>\n' % (_from, to, filename, linenum, text)


    def _note_event(cls, note_or_event='', entity1=None, entity2=None, text='', filename=None, linenum=None):

        if entity1 is None:
            # need at least one entity
            return

        if filename is None or linenum is None:
            # no embedded link
            textstr = text
        else:
            textstr = '<a href="#%s#%s">%s</a>' % (filename, linenum, text)

        if entity2 is None:
            # note over a single entity
            cls.html += '<%s for="%s">%s</%s>\n' % (note_or_event, entity1, textstr, note_or_event)
        else:
            # note spans 2 or more enitities
            cls.html += '<%s from="%s" to="%s">%s</%s>\n' % (note_or_event, entity1, entity2, textstr, note_or_event)


    def note(cls, entity1=None, entity2=None, text='', filename=None, linenum=None):
        cls._note_event('note', entity1, entity2, text, filename, linenum)

    def event(cls, entity1=None, entity2=None, text='', filename=None, linenum=None):
        cls._note_event('event', entity1, entity2, text, filename, linenum)

    def get_html(cls):
        return cls.html + '''
                </sequence-diagram-semantic>
    		<script>sequenceDiagram.convert(document.querySelector(".ui-layout-center.ui-layout-pane.ui-layout-pane-center"))</script>
        '''

def buildSequenceDiagram(proxyList):
    global gLogList, gCallList

    # Sort the log list
    sortedLogs = sorted(gLogList, key=lambda x: getattr(x, 'timestamp'))

    # Find out how many endpoints are involved across all of the calls
    phone1set = set()
    phone2set = set()
    for call in gCallList:
        phone1set.add(call.proxyList[0].fromIP)
        phone2set.add(call.proxyList[5].toIP)

    origPhoneIP = proxyList[0].fromIP
    destPhoneIP = proxyList[5].toIP
    proxy0Entity     = 'Proxy0'
    proxy1Entity     = 'Proxy1'
    b2bua1Entity     = 'B2BUA1'
    proxy2Entity     = 'Proxy2'
    cucmEntity       = 'CUCM'
    proxy3Entity     = 'Proxy3'
    b2bua2Entity     = 'B2BUA2'
    proxy4Entity     = 'Proxy4'
    proxy5Entity     = 'Proxy5'
    entityList = [proxy0Entity, proxy1Entity, b2bua1Entity, proxy2Entity, cucmEntity, proxy3Entity, b2bua2Entity, proxy4Entity, proxy5Entity]
    sdEntities = list(phone1set)
    sdEntities.extend(entityList)
    sdEntities.extend(list(phone2set))
    sd = SequenceDiagram(sdEntities)

    for log in sortedLogs:
        # search for the phone IPs, CUCM IP, or the this pointer in our proxy list
        if log.this in phone1set:
            if log.direction == 'rcvd':
                sd.action(log.this, proxy0Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(proxy0Entity, log.this, log.shortLog, log.filename, log.linenum)
        elif log.this in phone2set:
            if log.direction == 'rcvd':
                sd.action(log.this, proxy5Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(proxy5Entity, log.this, log.shortLog, log.filename, log.linenum)
        elif log.this == 'b2bua1in':
            if log.direction == 'rcvd':
                sd.action(proxy1Entity, b2bua1Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(b2bua1Entity, proxy1Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'b2bua1out':
            if log.direction == 'rcvd':
                sd.action(proxy2Entity, b2bua1Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(b2bua1Entity, proxy2Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'b2bua2in':
            if log.direction == 'rcvd':
                sd.action(proxy3Entity, b2bua2Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(b2bua2Entity, proxy3Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'b2bua2out':
            if log.direction == 'rcvd':
                sd.action(proxy4Entity, b2bua2Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(b2bua2Entity, proxy4Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'cucmIn':
            if log.direction == 'sent':
                sd.action(proxy2Entity, cucmEntity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'rcvd':
                sd.action(cucmEntity, proxy2Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'cucmOut':
            if log.direction == 'sent':
                sd.action(proxy3Entity, cucmEntity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'rcvd':
                sd.action(cucmEntity, proxy3Entity, log.shortLog, log.filename, log.linenum)

        # elif log.this == 'proxy0in':
        #     if log.direction == 'rcvd':
        #         sd.action(phone1Entity, proxy0Entity, log.shortLog, log.filename, log.linenum)
        #     elif log.direction == 'sent':
        #         sd.action(proxy0Entity, phone1Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'proxy0out':
            if log.direction == 'rcvd':
                sd.action(log.srcEntity, proxy0Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(proxy0Entity, proxy1Entity, log.shortLog, log.filename, log.linenum)
        elif log.this == 'proxy5in':
            if log.direction == 'rcvd':
                sd.action(log.srcEntity, proxy5Entity, log.shortLog, log.filename, log.linenum)
            elif log.direction == 'sent':
                sd.action(proxy5Entity, proxy4Entity, log.shortLog, log.filename, log.linenum)
        # elif log.this == 'proxy5out':
        #     if log.direction == 'rcvd':
        #         sd.action(phone2Entity, proxy5Entity, log.shortLog, log.filename, log.linenum)
        #     elif log.direction == 'sent':
        #         sd.action(proxy5Entity, phone2Entity, log.shortLog, log.filename, log.linenum)

    return sd.get_html()

def getTestHtml():
    html = '''
    		<sequence-diagram-semantic>
                <header>
    				<entity>Alice</entity>
    				<entity>Bob</entity>
    				<entity>Carol</entity>
    				<entity>Dani</entity>
    			</header>

    			<action><from>Alice</from> says hello to <to>Carol</to></action>
    			<note><from>Carol</from> is a nice person</note>
    			<event>
    				<from>Dani</from> enters:
    				<pre><code class="lang-json">{"foo": "bar"}</code></pre>
    			</event>

    			<section>
    				<title>Second section</title>
    				<group>
    					<lifeline><for>Bob</for>'s private conversation</lifeline>
    					<action><from>Alice</from> talks to <to>Bob</to></action>
    					<action from="Bob" to="Alice">replies</action>
    					<group>
    						<lifeline><from>Bob</from>'s distraction</lifeline>
    						<action><from>Alice</from> talks to <to>Bob</to></action>
    						<action><hidden><to>Alice</to></hidden> gets reply <hidden>from <from>Bob</from></hidden></action>
    					</group>
    					<action><to>Alice</to> gets conclusion from <from>Bob</from></action>
    				</group>
    			</section>
    		</sequence-diagram-semantic>
    		<script>sequenceDiagram.convert(document.querySelector(".ui-layout-center.ui-layout-pane.ui-layout-pane-center"))</script>
        '''
    return html


def save_globals():
    global gCallList, gProxyList, gLogList, gExpEIP, gExpCIP, gCucmIP, gRouteMapE, gRouteMapC, gPacketRelayMapE, gPacketRelayMapC, gPacketRelayMapTurn, gPortAssignment, gB2buaPortAssignment
    with open("calls.dat", "wb") as f:
        pickle.dump(gCallList, f)
    with open("proxy.dat", "wb") as f:
        pickle.dump(gProxyList, f)
    with open("logs.dat", "wb") as f:
        pickle.dump(gLogList, f)
    with open("ips.dat", "wb") as f:
        pickle.dump([gExpEIP, gExpCIP, gCucmIP], f)
    with open("routemaps.dat", "wb") as f:
        pickle.dump([gRouteMapE, gRouteMapC], f)
    with open("packetrelay.dat", "wb") as f:
        pickle.dump([gPacketRelayMapE, gPacketRelayMapE, gPacketRelayMapTurn], f)
    with open("portassignments.dat", "wb") as f:
        pickle.dump([gPortAssignment, gB2buaPortAssignment], f)

def load_globals():
    global gCallList, gProxyList, gLogList, gExpEIP, gExpCIP, gCucmIP, gRouteMapE, gRouteMapC, gPacketRelayMapE, gPacketRelayMapC, gPacketRelayMapTurn, gPortAssignment, gB2buaPortAssignment
    try:
        with open("calls.dat") as f:
            gCallList = pickle.load(f)
        with open("proxy.dat") as f:
            gProxyList = pickle.load(f)
        with open("logs.dat") as f:
            gLogList = pickle.load(f)
        with open("ips.dat") as f:
            gExpEIP, gExpCIP, gCucmIP = pickle.load(f)
        with open("routemaps.dat") as f:
            gRouteMapE, gRouteMapC = pickle.load(f)
        with open("packetrelay.dat") as f:
            gPacketRelayMapE, gPacketRelayMapC, gPacketRelayMapTurn = pickle.load(f)
        with open("portassignments.dat") as f:
            gPortAssignment, gB2buaPortAssignment = pickle.load(f)
    except:
        print "Error reading files"


@app.route('/')
def index():
    return render_template('upload.html')

#                       ExpE               ExpC              CUCM          Internal ExpC (if natted)
gIpMap = {'bud':    ['10.81.54.5',     '10.81.54.102',   '10.81.54.105',   None],
          'mandar': ['172.18.198.210', '172.18.198.211', '172.18.198.212', None],
          'wei':    ['172.18.194.52',  '172.18.202.226', '200.1.1.11',     '200.1.1.102'], # Call goes through wsun2-test2
          'wei3':   ['172.18.194.62',  '172.18.202.226', '200.1.1.11',     '200.1.1.102'], # Call goes through wsun2-test3
          'slteam': ['10.89.67.40',    '10.89.67.42',    '10.89.118.41',   None]}

@app.route('/uploader', methods=['GET', 'POST'])
def upload_file():
    global gExpEIP, gExpCIP, gCucmIP, gExpCInternalIP, gProxyList, gRouteMapE, gRouteMapC

    # Called from the form input with filenames
    if request.method == 'POST':
        expeFilename = None
        expcFilename = None
        turnFilename = None
        expcFile = request.files.get('fileC', None)
        expeFile = request.files.get('fileE', None)
        turnFile = request.files.get('fileTURN', None)

        # Check if at least one file is given
        if expcFile is None and expeFile is None:
            return 'Please go back and select at least one log file, an Expressway-E log file, an Expressway-C log file or both.'

        # Expressway-E log file
        if expeFile is not None:
            # Save the file locally
            expeFilename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(expeFile.filename))
            expeFile.save(expeFilename)

        # Expressway-C log file
        if expcFile is not None:
            # Save the file locally
            expcFilename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(expcFile.filename))
            expcFile.save(expcFilename)

        # TURN server log file. This is only needed if the TURN server is not the same as the Exp-E above
        if turnFile is not None:
            # Save the file locally
            turnFilename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(turnFile.filename))
            turnFile.save(turnFilename)

        # Set IP addrs
        if request.form.get('deployment', 'other') != 'other':
            # User selected known deployment
            gExpEIP, gExpCIP, gCucmIP, gExpCInternalIP = gIpMap[request.form.get('deployment')]
        else:
            # Custom deployment
            gExpEIP = request.form.ipE
            gExpCIP = request.form.ipC
            gCucmIP = request.form.ipCucm

            # Check if they gave us an IP address for the internal ExpC
            try:
                socket.inet_aton(request.form.ipInternalC)
                # legal IP
                gExpCInternalIP = request.form.ipCucm
            except socket.error:
                # illegal IP, assume not needed
                gExpCInternalIP = None

        # Parse the files!!
        gProxyList, gRouteMapE, gRouteMapC = initialize(expeFilename, expcFilename, turnFilename)

        asciiProxyTable = getProxyTable(gProxyList)
        print
        print "PROXY TABLE"
        print asciiProxyTable

        # asciiMsgTable = getCallFlowTable(gProxyList, gRouteMapE, gRouteMapC)
        # print
        # print "MSG TABLE"
        # print asciiMsgTable.get_string(sortby="Timestamp")

        save_globals()
        # listOfRows = getListOfMsgFlowRows(gProxyList, gRouteMapE, gRouteMapC)
        # table = MsgFlowTable(listOfRows, html_attrs={'frame': 'border', 'rules': 'cols'})
        # htmlMsgTable = Markup(table.__html__())
        # return render_template('ajax_layout.html', flow=htmlMsgTable)
        html = buildSequenceDiagram(gProxyList)
        return render_template('ajax_layout.html', flow=Markup(html))

@app.route('/check_log_levels')
def check_log_levels():
    try:
        url = 'https://vm-bluck-fed-vcse1.cisco.com/getxml?location=/Status/Loggers/Logger[Module = "developer.sip.leg"]'
        r = requests.get(url, verify=False)
        print r.text
        print r.status_code
        return r.status_code + '\n' + r.text
    except requests.exceptions.RequestException as e:
        print e
        return "Cannot connect to Expressway, check your network connection and verify the Expressway is up and running."

@app.route('/get_packet_relay_info_e')
def get_packet_relay_info_e():
    global gPacketRelayMapE
    ptE = getPacketRelayTable(gPacketRelayMapE)
    data = "EXPRESSWAY-E PACKET RELAY\n"
    data += ptE.get_string(sortby="Timestamp")
    return '<pre>' + data + '</pre>'

@app.route('/get_packet_relay_info_c')
def get_packet_relay_info_c():
    global gPacketRelayMapC
    ptE = getPacketRelayTable(gPacketRelayMapC)
    data = "EXPRESSWAY-C PACKET RELAY\n"
    data += ptE.get_string(sortby="Timestamp")
    return '<pre>' + data + '</pre>'

@app.route('/get_packet_relay_info_turn')
def get_packet_relay_info_turn():
    global gPacketRelayMapTurn
    ptT = getPacketRelayTable(gPacketRelayMapTurn)
    data = "TURN PACKET RELAY\n"
    data += ptT.get_string(sortby="Timestamp")
    return '<pre>' + data + '</pre>'

@app.route('/get_proxy_legs_e')
def get_proxy_legs_e():
    global gProxyLegMapE
    proxyLegTable = getProxyLegTable(gProxyLegMapE)
    data = "EXPRESSWAY-E PROXY LEGS\n"
    data += proxyLegTable.get_string(sortby="Order")
    return '<pre>' + data + '</pre>'

@app.route('/get_proxy_legs_c')
def get_proxy_legs_c():
    global gProxyLegMapC
    proxyLegTable = getProxyLegTable(gProxyLegMapC)
    data = "EXPRESSWAY-C PROXY LEGS\n"
    data += proxyLegTable.get_string(sortby="Order")
    return '<pre>' + data + '</pre>'

@app.route('/get_proxy_table')
def get_proxy_table():
    global gCallList
    data = "CALLS\n"
    for call in gCallList:
        data += "\nSessionID: %s  RemoteSessionID: %s\n" % (call.sessionID, call.remoteSessionID)
        proxyTable = getProxyTable(call.proxyList)
        data += proxyTable.get_string()
        data += "\n"
    return '<pre>' + data + '</pre>'

@app.route('/get_ascii_table')
def get_ascii_table():
    global gProxyList, gRouteMapE, gRouteMapC

    asciiMsgTable = getCallFlowTable(gProxyList, gRouteMapE, gRouteMapC)
    data = "ASCII MSG TABLE\n"
    data += asciiMsgTable.get_string(sortby="Timestamp")
    return '<pre>' + data.replace('<', '&lt') + '</pre>'

@app.route('/save_data')
def save_table():
    # Save the currently built table to a well-known file. This could be updated to save multiple tables
    # with an id, description, date, associated log files, etc.
    save_globals()
    print 'Saved!'
    return 'Success'

@app.route('/load_table')
def load_table():
    # Load previously saved data from files, build the table, and return the html. Only one saved table can be
    # returned at the moment.
    global gProxyList, gRouteMapE, gRouteMapC
    load_globals()

    listOfRows = getListOfMsgFlowRows(gProxyList, gRouteMapE, gRouteMapC)
    mtable = MsgFlowTable(listOfRows, html_attrs={'frame': 'border', 'rules': 'cols'})
    return mtable.__html__()

@app.route('/load_sequence_diagram')
def load_sequence_diagram():
    # Load previously saved data from files, build a sequence diagram, and return the html. Only one saved table can be
    # returned at the moment.
    global gProxyList
    load_globals()
    html = buildSequenceDiagram(gProxyList)
    return html

@app.route('/load_main_empty')
def load_main_empty():
    # Render the main page without any call flow loaded. The flow can be loaded from links on the main page.
    return render_template('ajax_layout.html', flow='')

@app.route('/get_file/')
def get_file():
    linenum = request.args.get('line')
    txtfilename = request.args.get('file')
    htmlfilename = os.path.splitext(txtfilename)[0] + '.html'

    try:
        # See if we've already parsed this file
        htmlfile = open(htmlfilename)

    except IOError:
        # Parse the file, build the html, save the html version into a new file in case requested again
        try:
            txtfile = open(txtfilename)
        except IOError:
            return 'File not found; start over and resubmit your log files.'

        htmlfile = open(htmlfilename, 'w')
        htmlfile.write("<style> p { margin: 0; font-family: courier; white-space: nowrap; font-size: small }</style>")
        linenum = 0
        for line in txtfile:
            linenum += 1
            newline = '%4d' % linenum + ' ' + line
            newline = newline.rstrip().replace('&', '&amp;').replace('<', '&lt;').replace(' ', '&nbsp;')
            #newline = re.sub(r'UTCTime="([^"]+)"', r'UTCTime="<b>\1</b>"', newline)
            newline = re.sub(r'Local-ip="([0-9.]+)"', r'Local-ip="<b>\1</b>"', newline)
            newline = re.sub(r'Dst-ip="([0-9.]+)"', r'Dst-ip="<b>\1</b>"', newline)
            newline = re.sub(r'Src-ip="([0-9.]+)"', r'Src-ip="<b>\1</b>"', newline)
            newline = re.sub(r'\|([A-Z]+)&nbsp;([^&]+)&nbsp;SIP/2.0', r'|<b>\1</b>&nbsp;\2&nbsp;SIP/2.0', newline)
            newline = re.sub(r'\|SIP/2.0&nbsp;([\w&;]+)$', r'|SIP/2.0&nbsp;<b>\1</b>', newline)
            html = '<p id=line-' + str(linenum) + '>' + newline + '</p>'
            htmlfile.write(html+'\n')
        htmlfile.close()
        htmlfile = open(htmlfilename)

    # Return only a snippet of the file, otherwise the browser will slow to a crawl
    html = '<style> p { margin: 0; font-family: courier; white-space: nowrap; font-size: small }</style>\n'
    firstline = int(linenum) - 1000
    if firstline < 1:
        firstline = 1
    lastline = int(linenum) + 1000
    for currline, line in enumerate(htmlfile):
        if currline > lastline:
            break
        if currline >= firstline:
            html += line
    return html

def main_html():
    app.run(host='localhost', port=8051, debug=True)
    return


def main_text():
    expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Michael_Logs/ice_defaultrelayAB_caller_holdresume_bad_audio_2/loggingsnapshot_rcdn6-vm67-40_2018-01-18_17_39_46.txt"
    expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Michael_Logs/ice_defaultrelayAB_caller_holdresume_bad_audio_2/loggingsnapshot_rcdn6-vm67-42_2018-01-18_17_39_52.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Michael_Logs/ice_defaultrelayAB_holdresume/loggingsnapshot_rcdn6-vm67-40_2018-01-17_22_09_09.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Michael_Logs/ice_defaultrelayAB_holdresume/loggingsnapshot_rcdn6-vm67-42_2018-01-17_22_09_06.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Wei_Logs/ice_synergylite_defaultrelayAB_holdresumeAworks_holdresumeBnomedia/loggingsnapshot_wsun2-test2_2018-01-12_22_07_53.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Wei_Logs/ice_synergylite_defaultrelayAB_holdresumeAworks_holdresumeBnomedia/loggingsnapshot_c038-expc_2018-01-12_22_07_47.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Wei_Logs/ice_synergylite_defaultrelayAB_holdresumeAworks_holdresumeBnomedia/loggingsnapshot_wsun2-test2_2018-01-12_21_40_56.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/Wei_Logs/ice_synergylite_defaultrelayAB_holdresumeAworks_holdresumeBnomedia/loggingsnapshot_c038-expc_2018-01-12_21_40_51.txt"
    #expeFilename = "/Users/bluck/Downloads/loggingsnapshot_wsun2-test2_2018-01-11_21_33_11.txt"
    #expcFilename = "/Users/bluck/Downloads/loggingsnapshot_c038-expc_2018-01-11_21_33_13.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-prototype/mra_expe.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-prototype/mra_expc.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-a-defaultrelay-b-defaultrelay/attempt2/mandar_ice_a_defaultrelay_b_defaultrelay_vcse.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-a-defaultrelay-b-defaultrelay/attempt2/mandar_ice_a_defaultrelay_b_defaultrelay_vcsc.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-prototype/mra_expe.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-prototype/mra_expc.txt"
    #expeFilename = "/Users/bluck/Downloads/diagnostic_log_vm-bluck-fed-vcse1_2018-01-08_11:35:38/loggingsnapshot_vm-bluck-fed-vcse1_2018-01-08_11:35:38.txt"
    #expcFilename = "/Users/bluck/Downloads/diagnostic_log_vm-bluck-fed-cust2-vcsc1_2018-01-08_11:35:43/loggingsnapshot_vm-bluck-fed-cust2-vcsc1_2018-01-08_11:35:43.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/non-ice-hold-resume/mandar_nonice_holdresume_vcse.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/non-ice-hold-resume/mandar_nonice_holdresume_vcsc.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-basic-call/mandar_ice_basiccall_vcse.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-basic-call/mandar_ice_basiccall_vcsc.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-mutual-hold/mandar_ice_mutualhold_vcse.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-mutual-hold/mandar_ice_mutualhold_vcsc.txt"
    #expeFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-a-defaultrelay-b-defaulthost/mandar_ice_a_defaultrelay_b_defaulthost_vcse.txt"
    #expcFilename = "/Users/bluck/Documents/ICE/logs/Parsing/My_Logs/with-mandars-diffs/ice-a-defaultrelay-b-defaulthost/mandar_ice_a_defaultrelay_b_defaulthost_vcsc.txt"
    proxyList, routeMapE, routeMapC = initialize(expeFilename, expcFilename)
    proxyTable = getProxyTable(proxyList)
    print
    print "PROXY TABLE"
    print proxyTable
    msgTable = getCallFlowTable(proxyList, routeMapE, routeMapC)
    print
    print "MSG TABLE"
    print msgTable.get_string(sortby="Timestamp")

    return

def main():
    global gExpEIP, gExpCIP, gCucmIP
    #gOrigPhoneIP = '10.122.73.183'
    #gDestPhoneIP = '10.122.73.147'
    # gExpEIP = '10.81.54.5'
    # gExpCIP = '10.81.54.102'
    # gCucmIP = '10.81.54.105'
    #main_text()
    main_html()

if __name__ == "__main__":
    main()