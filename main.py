from Tkinter import *
from ttk import *
import socket
import thread
from ecdsa import SigningKey, VerifyingKey
import base64

signing_key = SigningKey.generate()


class ChatClient(Frame):
    def __init__(self, root):
        Frame.__init__(self, root)
        self.root = root
        self.initUI()
        self.serverSoc = None
        self.serverStatus = 0
        self.buffsize = 2048
        self.allClients = {}
        self.counter = 0
        self.public_keys = {}

    def initUI(self):
        self.root.title("Simple P2P Chat Client")
        ScreenSizeX = self.root.winfo_screenwidth()
        ScreenSizeY = self.root.winfo_screenheight()
        self.FrameSizeX = 800
        self.FrameSizeY = 600
        FramePosX = (ScreenSizeX - self.FrameSizeX) / 2
        FramePosY = (ScreenSizeY - self.FrameSizeY) / 2
        self.root.geometry(
            "%sx%s+%s+%s" % (self.FrameSizeX, self.FrameSizeY, FramePosX, FramePosY))
        self.root.resizable(width=False, height=False)

        padX = 10
        padY = 10
        parentFrame = Frame(self.root)
        parentFrame.grid(padx=padX, pady=padY, stick=E + W + N + S)

        ipGroup = Frame(parentFrame)
        serverLabel = Label(ipGroup, text="Set: ")
        self.nameVar = StringVar()
        self.nameVar.set("SDH")
        nameField = Entry(ipGroup, width=10, textvariable=self.nameVar)
        self.serverIPVar = StringVar()
        self.serverIPVar.set("127.0.0.1")
        serverIPField = Entry(ipGroup, width=15, textvariable=self.serverIPVar)
        self.serverPortVar = StringVar()
        self.serverPortVar.set("8090")
        serverPortField = Entry(ipGroup, width=5, textvariable=self.serverPortVar)
        serverSetButton = Button(ipGroup, text="Set", width=10,
                                 command=self.handleSetServer)
        addClientLabel = Label(ipGroup, text="Add friend: ")
        self.clientIPVar = StringVar()
        self.clientIPVar.set("127.0.0.1")
        clientIPField = Entry(ipGroup, width=15, textvariable=self.clientIPVar)
        self.clientPortVar = StringVar()
        self.clientPortVar.set("8091")
        clientPortField = Entry(ipGroup, width=5, textvariable=self.clientPortVar)
        clientSetButton = Button(ipGroup, text="Add", width=10,
                                 command=self.handleAddClient)
        serverLabel.grid(row=0, column=0)
        nameField.grid(row=0, column=1)
        serverIPField.grid(row=0, column=2)
        serverPortField.grid(row=0, column=3)
        serverSetButton.grid(row=0, column=4, padx=5)
        addClientLabel.grid(row=0, column=5)
        clientIPField.grid(row=0, column=6)
        clientPortField.grid(row=0, column=7)
        clientSetButton.grid(row=0, column=8, padx=5)

        readChatGroup = Frame(parentFrame)
        self.receivedChats = Text(readChatGroup, bg="white", width=60, height=30,
                                  state=DISABLED)
        self.friends = Listbox(readChatGroup, bg="white", width=30, height=30)
        self.receivedChats.grid(row=0, column=0, sticky=W + N + S, padx=(0, 10))
        self.friends.grid(row=0, column=1, sticky=E + N + S)

        writeChatGroup = Frame(parentFrame)
        self.chatVar = StringVar()
        self.chatField = Entry(writeChatGroup, width=80, textvariable=self.chatVar)
        sendChatButton = Button(writeChatGroup, text="Send", width=10,
                                command=self.handleSendChat)
        self.chatField.grid(row=0, column=0, sticky=W)
        sendChatButton.grid(row=0, column=1, padx=5)

        self.statusLabel = Label(parentFrame)

        bottomLabel = Label(parentFrame,
                            text="Created by Siddhartha under Prof. A. Prakash [Computer Networks, Dept. of CSE, BIT Mesra]")

        ipGroup.grid(row=0, column=0)
        readChatGroup.grid(row=1, column=0)
        writeChatGroup.grid(row=2, column=0, pady=10)
        self.statusLabel.grid(row=3, column=0)
        bottomLabel.grid(row=4, column=0, pady=10)

    def handleSetServer(self):
        if self.serverSoc != None:
            self.serverSoc.close()
            self.serverSoc = None
            self.serverStatus = 0
        serveraddr = (self.serverIPVar.get().replace(' ', ''),
                      int(self.serverPortVar.get().replace(' ', '')))
        try:
            self.serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serverSoc.bind(serveraddr)
            self.serverSoc.listen(5)
            self.setStatus("Server listening on %s:%s" % serveraddr)
            thread.start_new_thread(self.listenClients, ())
            self.serverStatus = 1
            self.name = self.nameVar.get().replace(' ', '')
            if self.name == '':
                self.name = "%s:%s" % serveraddr
        except Exception as e:
            self.setStatus("Error setting up server: " + str(e))

    def listenClients(self):
        while 1:
            clientsoc, clientaddr = self.serverSoc.accept()
            self.setStatus("Client connected from %s:%s" % clientaddr)
            public_key = clientsoc.recv(self.buffsize)
            clientsoc.send(signing_key.verifying_key.to_string())
            self.addClient(clientsoc, clientaddr, public_key)
            thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
        self.serverSoc.close()

    def handleAddClient(self):
        if self.serverStatus == 0:
            self.setStatus("Set server address first")
            return
        clientaddr = (self.clientIPVar.get().replace(' ', ''),
                      int(self.clientPortVar.get().replace(' ', '')))
        try:
            clientsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsoc.connect(clientaddr)
            self.setStatus("Connected to client on %s:%s" % clientaddr)
            clientsoc.send(signing_key.verifying_key.to_string())
            public_key = clientsoc.recv(self.buffsize)
            self.addClient(clientsoc, clientaddr, public_key)
            thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
        except Exception as e:
            self.setStatus("Error connecting to client: " + str(e))

    def handleClientMessages(self, clientsoc, clientaddr):
        while 1:
            try:
                data = clientsoc.recv(self.buffsize)
                if not data:
                    break
                msg, signature = data.split('###')
                signature = base64.b64decode(signature)
                if self._verify(msg, signature, clientsoc):
                    msg += ' (verified)'
                else:
                    msg += ' (unverified !!!!)'
                self.addChat("%s:%s" % clientaddr, msg)
            except Exception as e:
                print(e)
                break
        self.removeClient(clientsoc, clientaddr)
        clientsoc.close()
        self.setStatus("Client disconnected from %s:%s" % clientaddr)

    def handleSendChat(self):
        if self.serverStatus == 0:
            self.setStatus("Set server address first")
            return
        msg = self.chatVar.get().replace(' ', '')
        if msg == '':
            return
        self.addChat("me", msg)
        signed_msg = self._sign(msg)
        for client in self.allClients.keys():
            print client
            client.send(signed_msg)

    def addChat(self, client, msg):
        self.receivedChats.config(state=NORMAL)
        self.receivedChats.insert("end", client + ": " + msg + "\n")
        self.receivedChats.config(state=DISABLED)

    def addClient(self, clientsoc, clientaddr, public_key):
        self.public_keys[clientsoc] = public_key
        self.allClients[clientsoc] = self.counter
        self.counter += 1
        public_key_b64 = base64.b64encode(public_key)
        self.friends.insert(self.counter, "%s:%s public_key=%s" % (clientaddr[0], clientaddr[1], public_key_b64))

    def removeClient(self, clientsoc, clientaddr):
        print self.allClients
        self.friends.delete(self.allClients[clientsoc])
        del self.allClients[clientsoc]
        print self.allClients

    def setStatus(self, msg):
        self.statusLabel.config(text=msg)
        print msg

    def _verify(self, msg, signature, clientsoc):
        public_key = VerifyingKey.from_string(self.public_keys[clientsoc])
        return public_key.verify(signature, msg)

    def _sign(self, msg):
        signature = signing_key.sign(msg)
        return msg + '###' + base64.b64encode(signature)


def main():
    root = Tk()
    app = ChatClient(root)
    root.mainloop()


if __name__ == '__main__':
    main()
