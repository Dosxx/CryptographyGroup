# ICS483 Group Project
# Authors: Kekeli D Akouete, Vang Uni A
# Implementing encryption in an application

from tkinter import filedialog
from tkinter import *
from tkinter import messagebox
#UV: Not sure if we need bottom import line since we import * from tkinter already
#from tkinter import Tk, Text, TOP, RIGHT, LEFT, BOTH, X, N, RAISED
from tkinter.ttk import Frame, Label, Entry, Button, Style
import os
from MyCipher import MyCipher

root = Tk()
cipher = MyCipher()
menu = Menu(root)
root.config(menu=menu)
fileMenu = Menu(menu)

def showHelp():
    messagebox.showinfo(title="About", message=readFile("help.txt"))

def openFile():
    myFile = filedialog.askopenfilename()
    # displayfilename.configure(text="File Name: " + myFile + "\n")
    # displayfilecontent.configure(text="File Content: " + readFile(myFile) + "\n")

def saveAs():
    filedialog.asksaveasfilename()

# Definition of the read method which takes a file
def readFile(filename):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            file_content = file.read()
            return file_content
    else:
        print("File not found")

def createFile():
    file = open("cryptography.txt","w+")
    file.write("The lazy dog chasese after the quick brown fox.")
    file.close

# Definition of the write method
def writeFile(context, filename):
    if type(context) == bytes:
        context.decode()
    with open(filename, "w") as file:
        file.write(context)
        file.seek(0)
 
#root = Tk()

def main():

    #root = Tk()
    root.geometry("400x200")
    #root.geometry("300x300+300+300")
    crypto_app = Window()   #Variable not used
    crypto_app.master.maxsize(750, 530)
    crypto_app.master.protocol("WM_DELETE_WINDOW", quitApp)
    root.mainloop()

def quitApp():
    if messagebox.askokcancel("Confirm Exit", "Do you really wish to quit?"):
        root.destroy()

# Menu bar items
#fileMenu = Menu(menu)
menu.add_cascade(label="File", menu=fileMenu)
fileMenu.add_command(label="Open", command=openFile)
fileMenu.add_command(label="Save As", command=saveAs)
fileMenu.add_command(label="Create File", command=createFile)
fileMenu.add_command(label="Exit", command=quitApp)

actionMenu = Menu(menu)
menu.add_cascade(label="Action", menu=actionMenu)
actionMenu.add_command(label="Decrypt")
actionMenu.add_command(label="Encrypt")
actionMenu.add_command(label="Generate key", command=cipher.keygen())

helpMenu = Menu(menu)
menu.add_cascade(label="Help", menu=helpMenu)
helpMenu.add_command(label="About", command=showHelp)


######################### MAIN WINDOW ITEMS #########################

# labels = ['Input From File:', 'Key:', 'IV:', 'Output:']
# r = 0
# for label in labels:
#     Label(text=label, width=15, padx=10, pady=10, justify=RIGHT).grid(row=r, column=0)
#     Entry(relief=SUNKEN, width=10).grid(row=r, column=1, columnspan=3, sticky=EW)
#     r = r + 1

class Window(Frame):

    def __init__(self):
        super().__init__()

        self.initUI()


    def initUI(self):
        master = self.master
        master.title("Cryptographer1.0")
        self.pack(fill=BOTH, expand=True)
        self.style = Style()
        self.style.theme_use("default")

        frame1 = Frame(self)
        frame1.pack(fill=X)
        fileLabel = Label(frame1, text="Input File:", width=9)
        fileLabel.pack(side=LEFT, padx=5, pady=5)
        fileEntry = Entry(frame1)
        fileEntry.pack(fill=X, padx=5, expand=True)

        frame2 = Frame(self)
        frame2.pack(fill=X)
        keyLabel = Label(frame2, text="Key:", width=9)
        keyLabel.pack(side=LEFT, padx=5, pady=5)
        keyEntry = Entry(frame2)
        keyEntry.pack(fill=X, padx=5, expand=True)

        frame3 = Frame(self)
        frame3.pack(fill=X)
        ivLabel = Label(frame3, text="IV:", width=9)
        ivLabel.pack(side=LEFT, padx=5, pady=5)
        ivEntry = Entry(frame3)
        ivEntry.pack(fill=X, padx=5, expand=True)

        frame4 = Frame(self)
        frame4.pack(fill=X)
        outputLabel = Label(frame4, text="Output:", width=9)
        outputLabel.pack(side=LEFT, padx=5, pady=5)
        outputResultLabel = Label(frame4, text="RESULT GENERATED HERE")
        outputResultLabel.pack(side=LEFT, padx=5, pady=5)

        frame5 = Frame(self, relief=RAISED, borderwidth=0)
        frame5.pack(fill=BOTH, expand=True)
        decryptButton = Button(frame5, text="Decrypt", command=quitApp)
        decryptButton.pack(side=RIGHT, padx=5, pady=5)
        encryptButton = Button(frame5, text="Encrypt", command=quitApp)
        encryptButton.pack(side=RIGHT, padx=5)

        frame6 = Frame(self)
        frame6.pack(fill=X)
        status = Label(frame6, text="Cryptographer_1.0 \u00AE All rights reserved", justify=CENTER)
        status.pack(side=BOTTOM, padx=5, pady=10, anchor=S)
        
if __name__ == '__main__':
    main()