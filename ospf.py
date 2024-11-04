# Bootleg packet tracer (Real)
RouterGraph = dict() # Adj Dict, the birds eye view of the network that the routers dont get
'''
{
    4 : [(2, "A", "B", 3), (4, "B", "B", 9)]
    Source Router ID : Cost, Source Port, Dest Port, Dest Router
}
'''
RouterIDToObject = dict()

ROUTER_HELLO_INTERVAL = 5
ROUTER_LSP_INTERVAL = 15
# This sim doesn't account for connection reliability, IRL there need to be more ACKS because a packet or two being dropped shouldn't lead to the conncetion being declared down
# It also doesn't account for travel time, etc.
def sendMessage(routerFrom, portTo, messageType, data=None):
    # Attempts to send the message to the router connected to the specified port. Returns if it was successful or not.
    global RouterGraph
    for x in RouterGraph[routerFrom]:
        if x[1] == portTo:
            RouterIDToObject[x[3]].recieveMessage(x[2], messageType, data)
            return True
    return False
            
class LSP:
    def __init__(self, originatorID, directNeighbors, SeqNum, TTL):
        self.origin = originatorID
        self.neighbors = directNeighbors
        self.seqNum = SeqNum
        self.TTL = TTL

    def decrementTTL(self):
        self.TTL -= 1

class Router:
    def __init__(self, ID, ports=set()):
        self.ID = ID
        self.ActivePorts = ports
        self.currentCounter = 0
        self.neighbors = dict() # port : (router ID, Cost)
        self.nodeLSPs = dict() # router ID: (highest SQ num, neighborData)
        self.Active = True
        self.HelloInterval = 0
        self.LSPInterval = 0
        self.nextTickActions = []
        # Generate LSP
    
    def tick(self):
        self.HelloInterval += 1
        self.LSPInterval += 1
        if self.HelloInterval > ROUTER_HELLO_INTERVAL:
            self.getNeigbors()
            self.HelloInterval = 0
        if self.LSPInterval > ROUTER_LSP_INTERVAL:
            self.genAndFloodLSP()
            self.LSPInterval = 0
        for act in self.nextTickActions:
            act(0)
        self.nextTickActions = []

    def connectPort(self, port):
        self.ActivePorts.add(port)
    
    def floodMessage(self, messageType, data, avoid=None):
        for p in self.ActivePorts:
            if p != avoid:
                sendMessage(self.ID, p, messageType, data)

    def recieveMessage(self, toPort, messageType, data=None):
        global RouterGraph
        if not self.Active:
            return None
        if messageType == 1: # Hello packet, there would be some like time calculations here normally but lets just say doing this gives the router knowlege of the edge weight
            if self.neighbors.get(toPort, -1) == -1:
                # Find the edge weight and update self.neighbors
                for adj in RouterGraph[self.ID]:
                    if adj[1] == toPort:
                        self.neighbors[toPort] = (data, adj[0])
                        self.nextTickActions.append(lambda x: self.genAndFloodLSP()) # TODO: Ensure dupe instructions are not added
                        break
        elif messageType == 2: # Recieving a LSP.
            SenderID = data.origin
            NeighborData = data.neighbors
            SeqN = data.seqNum
            LSPTTL = data.TTL
            # print("ttl", LSPTTL)
            if LSPTTL <= 0:
                if SenderID in self.nodeLSPs and self.nodeLSPs[SenderID][0] == SeqN: # The LSP is stale, remove.
                    del self.nodeLSPs[SenderID]
                    self.floodMessage(2, data, toPort)
                return None
            if SenderID not in self.nodeLSPs or self.nodeLSPs[SenderID][0] < SeqN:
                self.nodeLSPs[SenderID] = (SeqN, NeighborData)
            # Continue to flood the LSP on all ports that are not the one that this router recieved it from
            data.decrementTTL()
            self.nextTickActions.append(lambda x: self.floodMessage(2, data, toPort))
    
    def getNeigbors(self):
        change = False
        kill = []
        for p in self.ActivePorts:
            if not sendMessage(self.ID, p, 1, self.ID):
                # Declare port P down
                kill.append(p)
                change = True
        
        if change:
            for k in kill:
                self.ActivePorts.remove(k)
                del self.neighbors[k]
            self.genAndFloodLSP()
            # Generate new LSP
    
    def genAndFloodLSP(self):
        ThisLSP = LSP(self.ID, self.neighbors, self.currentCounter, 255)
        self.currentCounter += 1
        self.nextTickActions.append(lambda x: self.floodMessage(2, ThisLSP))
    
    def attemptRouting(self):
        Adj = dict()
        for node in self.nodeLSPs:
            Adj[node] = list(self.nodeLSPs[node][1].values())
        return Adj
        # Run Dijikstras

# Simple network:
# 1 A-----C 2
# B       B A
# |     /   |
# |   /     |
# A B       A
# 3         4
# 1 -> 2 : 2
# 1 -> 3 : 1
# 2 -> 3 : 5
# 2 -> 4 : 4
# The 1 -> 2 connection will go down at T = 10
ExR1 = Router(1, set(["A", "B"]))
ExR2 = Router(2, set(["A", "B", "C"]))
ExR3 = Router(3, set(["A", "B"]))
ExR4 = Router(4, set(["A"]))
RouterIDToObject[1] = ExR1
RouterIDToObject[2] = ExR2
RouterIDToObject[3] = ExR3
RouterIDToObject[4] = ExR4
RouterGraph = {
    1 : [(2, "A", "C", 2), (1, "B", "A", 3)],
    2 : [(2, "C", "A", 1), (5, "B", "B", 3), (4, "A", "A", 4)],
    3 : [(5, "B", "B", 2), (1, "A", "B", 1)],
    4 : [(4, "A", "A", 2)]
}
T = 0
while T < 100:
    for R in RouterIDToObject.values():
        R.tick()
        print(R.ID, R.attemptRouting())
    input()
    T += 1
    if T == 10:
        RouterGraph[1].pop(0)
        RouterGraph[2].pop(0)
        print("THEY JUST HIT THE 1 --> 2 CONNECTION")
    if T == 15:
        RouterGraph[3].append((3, "C", "B", 4))
        RouterGraph[4].append((3, "B", "C", 3))
        ExR3.connectPort("C")
        ExR4.connectPort("B")
        print("sir a second connection change has struck (welcome connection 3 -- 4)")

    print(T)