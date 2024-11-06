# Bootleg packet tracer (Real)
# TODO: Fix the repeated LSP messages
import pygame
from pygame.locals import *
from random import randint, sample
import sys
# SGR color constants
# rene-d 2018

class C:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"
    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    else:
        # set Windows console in VT mode
        if __import__("platform").system() == "Windows":
            kernel32 = __import__("ctypes").windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32

# RouterGraph = dict() # Adj Dict, the birds eye view of the network that the routers dont get
'''
{
    4 : [(2, "A", "B", 3), (4, "B", "B", 9)]
    Source Router ID : Cost, Source Port, Dest Port, Dest Router
}
'''
# RouterIDToObject = dict()

ROUTER_HELLO_INTERVAL = 10
ROUTER_LSP_INTERVAL = 1500

MessageTypeToHumanReadable = {
    1 : "HELLO",
    2 : "LSP"
}
# This sim doesn't account for connection reliability, IRL there need to be more ACKS because a packet or two being dropped shouldn't lead to the conncetion being declared down
# It also doesn't account for travel time, etc.
def sendMessage(routerFrom, portTo, messageType, data=None):
    # Attempts to send the message to the router connected to the specified port. Returns if it was successful or not.
    for x in FullNetwork.Connections[routerFrom] :
        if x[1] == portTo:  
            if messageType == 1:
                print(f"[i {T}] {MessageTypeToHumanReadable[messageType]} message from router {routerFrom} to router {x[3]}")
            FullNetwork.getRouter(x[3]).recieveMessage(x[2], messageType, data) # !
            return True
    print(f"{C.RED}[- {T}] Failed {MessageTypeToHumanReadable[messageType]} message from router {routerFrom} on port {portTo}{C.END}")
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
    def __init__(self, ID):
        self.ID = ID
        self.ActivePorts = set()
        self.currentCounter = 0
        self.neighbors = dict() # port : (router ID, Cost)
        self.nodeLSPs = dict() # router ID: (highest SQ num, neighborData)
        self.adjMatrix = dict()
        self.Active = True
        self.HelloInterval = randint(0, 25)
        self.LSPInterval = randint(0, 250)
        self.nextTickActions = []
        self.IDTextObject = None
        # Generate LSP
    
    def tick(self):
        self.HelloInterval += 1
        self.LSPInterval += 1
        if self.HelloInterval % ROUTER_HELLO_INTERVAL == 0:
            self.getNeigbors()
        if self.LSPInterval % ROUTER_LSP_INTERVAL == 0:
            self.genAndFloodLSP()
        for act in self.nextTickActions:
            act(0)
        self.nextTickActions = []

    def connectPort(self, port):
        self.ActivePorts.add(port)
    
    def floodMessage(self, messageType, data, avoid=None):
        kill = set()
        for p in self.ActivePorts:
            if p != avoid and p not in kill:
                if not sendMessage(self.ID, p, messageType, data):
                    # Confirm a failure of the port
                    if not sendMessage(self.ID, p, 1, self.ID):
                        kill.add(p)
        if len(kill) > 0:
            for k in kill:
                print(f"[! {T}] Removing port {k} from router {self.ID}'s active ports")
                self.ActivePorts.remove(k)
                del self.neighbors[k]

    def recieveMessage(self, toPort, messageType, data=None):
        if not self.Active:
            return None
        if messageType == 1: # Hello packet, there would be some like time calculations here normally but lets just say doing this gives the router knowlege of the edge weight
            if self.neighbors.get(toPort, -1) == -1: # This neighbor has not been considered yet
                # Find the edge weight and update self.neighbors
                for adj in FullNetwork.Connections[self.ID]:
                    if adj[1] == toPort:
                        self.neighbors[toPort] = (data, adj[0])
                        self.genAndFloodLSP() # TODO: Ensure dupe instructions are not added
                        break
        elif messageType == 2: # Recieving a LSP.
            SenderID = data.origin
            NeighborData = data.neighbors
            SeqN = data.seqNum
            LSPTTL = data.TTL
            # print("ttl", LSPTTL)
            if LSPTTL <= 0:
                if SenderID in self.nodeLSPs and self.nodeLSPs[SenderID][0] == SeqN: # The LSP is stale, remove.
                    print(f"{C.BLUE}[! {T}] Router {self.ID} recieved and is flooding a 0 TTL LSP message (SRC {SenderID} SEQ {SeqN} FWD {self.neighbors.get(toPort, ('UNKNOWN', 0))[0]}){C.END}")
                    del self.nodeLSPs[SenderID]
                    self.floodMessage(2, data, toPort)
                return None
            if SenderID not in self.nodeLSPs or SeqN > self.nodeLSPs[SenderID][0]:
                print(f"{C.GREEN}[+ {T}] Router {self.ID} accepts LSP with SRC {SenderID} SEQ {SeqN} FWD {self.neighbors.get(toPort, ('UNKNOWN', 0))[0]}{C.END}")
                self.nodeLSPs[SenderID] = (SeqN, NeighborData)
                for node in self.nodeLSPs:
                    self.adjMatrix[node] = list(self.nodeLSPs[node][1].values())
            else:
                print(f"{C.RED}[- {T}] Router {self.ID} denies LSP with SRC {SenderID} SEQ {SeqN} FWD {self.neighbors.get(toPort, ('UNKNOWN', 0))[0]} (More recent or equal LSP of SEQ {self.nodeLSPs[SenderID][0]}){C.END}")
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
                print(f"[i {T}] Declaring port {k} on router {self.ID} down")
                self.ActivePorts.remove(k)
                del self.neighbors[k]
            self.genAndFloodLSP()
            # Generate new LSP
    
    def genAndFloodLSP(self):
        ThisLSP = LSP(self.ID, self.neighbors, self.currentCounter, 50) # Usually TTL is set to 255
        self.currentCounter += 1
        self.nextTickActions.append(lambda x: self.floodMessage(2, ThisLSP))
    
    def attemptRouting(self):
        return self.adjMatrix
        Adj = dict()
        for node in self.nodeLSPs:
            Adj[node] = list(self.nodeLSPs[node][1].values())
        return Adj
        # Run Dijikstras
class Network:
    def __init__(self, RouterCount, ConnectionCount):
        self.size = RouterCount
        self.Routers = []
        self.RouterPositions = []
        self.Connections = {}
        searchconnect = set()
        for x in range(1, RouterCount+1):
            self.Routers.append(Router(x))
            self.Routers[-1].IDTextObject = Font.render(str(x), False, (0, 0, 0))
            self.RouterPositions.append((randint(0, DX - 100), randint(100, DY - 100)))
            self.Connections[x] = []
        for _ in range(ConnectionCount):
            R1, R2 = sample(list(range(1,RouterCount+1)), 2)
            if (R1, R2) not in searchconnect and (R2, R1) not in searchconnect:
                searchconnect.add((R1, R2))
                P1 = chr(len(self.getRouter(R1).ActivePorts) + 65)
                P2 = chr(len(self.getRouter(R2).ActivePorts) + 65)
                cost = randint(1, 50)
                self.Connections[R1].append([cost, P1, P2, R2])
                self.Connections[R2].append([cost, P2, P1, R1])
                self.getRouter(R1).connectPort(P1)
                self.getRouter(R2).connectPort(P2)
        self.RITTP = {o+1 : (self.getRouterPosition(o+1)[0] - 9,  self.getRouterPosition(o+1)[1] - 22) for o in range(RouterCount)}
    def getRouter(self, ID):
        return self.Routers[ID-1]
    def getRouterPosition(self, ID):
        return self.RouterPositions[ID-1]
    def getRITTP(self, ID):
        return self.RITTP[ID]
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
'''
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
'''
pygame.init()
Font = pygame.font.SysFont('Cambria', 30)
TickCount = Font.render("Tick 0", False, (0, 0, 0))
RouterView = Font.render("Viewing true map", False, (0, 0, 0))
SelectedRouter = 0

DX = 750
DY = 750
DISPLAYSURF = pygame.display.set_mode((DX, DY), flags=pygame.SCALED)

'''
RouterIDToPosition = {
    1 : (DX // 6, DX // 6),
    2 : (4 * DX // 6, DY // 6),
    3 : (DX // 6, 4 * DY // 6),
    4 : (4 * DX // 6, 4 * DY // 6)
}
RouterIDToPosition = {
    1 : (randint(150, 600), randint(150, 600)),
    2 : (randint(150, 600), randint(150, 600)),
    3 : (randint(150, 600), randint(150, 600)),
    4 : (randint(150, 600), randint(150, 600))
}
'''
NumKeys = set([K_0, K_1, K_2, K_3, K_4, K_5, K_6, K_7, K_8, K_9])

# RITTP = {o : (RouterIDToPosition[o][0] - 9, RouterIDToPosition[o][1] - 22) for o in RouterIDToPosition}
FullNetwork = Network(5, 9)

FramesPerSec = pygame.time.Clock()

FPS = 15
T = 0

while True:
    DISPLAYSURF.fill((255, 255, 255))
    TickCount = Font.render(f"Tick {T}", False, (0, 0, 0))
    if SelectedRouter == 0:
        RouterView = Font.render("Viewing full network", False, (0, 0, 0))
    else:
        RouterView = Font.render(f"Router {SelectedRouter} view", False, (0, 0, 0))
    DISPLAYSURF.blit(TickCount, (0, 0))
    DISPLAYSURF.blit(RouterView, (0, 30))
    for event in pygame.event.get():
        if event.type == QUIT:
            pygame.quit()
            sys.exit()
        if event.type == pygame.KEYDOWN:
            if event.key == K_SPACE:
                for _ in range(5):
                    print(f"Tick {T}")
                    for R in FullNetwork.Routers:
                        R.tick()
                    T += 1
            elif event.key in NumKeys:
                if event.key - 48 <= FullNetwork.size:
                    SelectedRouter = event.key - 48
    
    for node in FullNetwork.Connections:
        for edge in FullNetwork.Connections[node]:
            if SelectedRouter == 0:
                pygame.draw.line(DISPLAYSURF, (0, 0, 0), FullNetwork.getRouterPosition(node), FullNetwork.getRouterPosition(edge[3]), width=5)
            else:
                pygame.draw.line(DISPLAYSURF, (200, 200, 200), FullNetwork.getRouterPosition(node), FullNetwork.getRouterPosition(edge[3]), width=5)
    if SelectedRouter != 0:
        v = FullNetwork.getRouter(SelectedRouter).attemptRouting()
        for routerKey in v:
            for edge in v[routerKey]:
                pygame.draw.line(DISPLAYSURF, (0, 0, 0), FullNetwork.getRouterPosition(routerKey), FullNetwork.getRouterPosition(edge[0]), width=5)
    for o in range(1, FullNetwork.size + 1):
        if o == SelectedRouter: 
            pygame.draw.circle(DISPLAYSURF, (255, 0, 0), FullNetwork.getRouterPosition(o), 20)
        else:
            pygame.draw.circle(DISPLAYSURF, (0, 0, 0), FullNetwork.getRouterPosition(o), 20)
            pygame.draw.circle(DISPLAYSURF, (255, 255, 255), FullNetwork.getRouterPosition(o), 18)
        DISPLAYSURF.blit(FullNetwork.getRouter(o).IDTextObject, FullNetwork.getRITTP(o))
    pygame.display.update()
    FramesPerSec.tick(FPS)