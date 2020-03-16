# ICS483 Group Project
# Authors: Kekeli D Akouete, Vang Uni A
# Implementing encryption in an application

from tkinter import filedialog
from tkinter import *
from tkinter import messagebox
import os
from MyCipher import MyCipher


def saveAs():
    filedialog.asksaveasfilename()


# Definition of the read method which takes a file
def readfile(filename):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            file_content = file.read()
            return file_content

    else:
        print("File not found")


# Definition of the write method
def writefile(context, filename):
    if type(context) == bytes:
        context.decode()
    with open(filename, "w") as file:
        file.write(context)
        file.seek(0)


class Window(Frame):
    def __init__(self, master=None):
        # Frame.__init__(self, master)
        super().__init__(master)
        self.master = master
        menu = Menu(self.master)
        self.master.config(menu=menu)

        # Menu bar items
        fileMenu = Menu(menu)
        menu.add_cascade(label="File", menu=fileMenu)
        fileMenu.add_command(label="Open", command=self.openfile)
        fileMenu.add_command(label="Save As", command=saveAs)
        fileMenu.add_command(label="Create File")
        fileMenu.add_command(label="Exit", command=quitApp)

        actionMenu = Menu(menu)
        menu.add_cascade(label="Action", menu=actionMenu)
        actionMenu.add_command(label="Decrypt")
        actionMenu.add_command(label="Encrypt")
        actionMenu.add_command(label="Generate key", command=cipher.keygen())

        helpMenu = Menu(menu)
        menu.add_cascade(label="Help", menu=helpMenu)
        helpMenu.add_command(label="About", command=self.showhelp)

        # Main window items
        # labels = ['Input From File:', 'Key:', 'IV:', 'Output:']
        # r = 0
        # for label in labels:
        #     Label(text=label, width=15, padx=10, pady=10, justify=RIGHT).grid(row=r, column=0)
        #     Entry(relief=SUNKEN, width=10).grid(row=r, column=1, columnspan=3, sticky=EW)
        #     r = r + 1

        fileLabel = Label(text="File Name: ", width=15, padx=10, pady=10, justify=RIGHT, anchor=W)
        fileLabel.pack(side=LEFT)
        fileEntry = Entry(width=10, relief=SUNKEN)
        fileEntry.pack(side=LEFT, expand=YES, fill=X)
        keyLabel = Label(text="Key: ", width=15, padx=10, pady=10, justify=RIGHT, anchor=W)
        keyLabel.pack(side=LEFT)
        keyEntry = Entry(width=10, relief=SUNKEN)
        keyEntry.pack(side=LEFT, expand=YES, fill=X)
        ivLabel = Label(text="IV: ", width=15, padx=10, pady=10, justify=RIGHT, anchor=W)
        ivLabel.pack(side=LEFT)
        ivEntry = Entry(width=10, relief=SUNKEN)
        ivEntry.pack(side=LEFT, expand=YES, fill=X)
        outputLabel = Label(text="Output: ", relief=SUNKEN, width=15, padx=10, pady=5, justify=RIGHT, anchor=W)
        outputLabel.pack(side=LEFT)

        # self.label.place(x=8, y=15)

        # Application footer items
        status = Label(text="Cryptographer_1.0 \u00AE All rights reserved",
                       bd=1,
                       relief=SUNKEN,
                       justify=LEFT,
                       anchor=W)
        status.pack(side=BOTTOM, expand=YES, fill=X)
        # self.pack()

    @staticmethod
    def showhelp():
        messagebox.showinfo(title="About", message=readfile("help.txt"))

    @staticmethod
    def openfile():
        myFile = filedialog.askopenfilename()
        # displayfilename.configure(text="File Name: " + myFile + "\n")
        # displayfilecontent.configure(text="File Content: " + readfile(myFile) + "\n")


def quitApp():
    if messagebox.askokcancel("Confirm Exit", "Do you really wish to quit?"):
        root.destroy()


root = Tk()
cipher = MyCipher()
crypto_app = Window(root)
crypto_app.master.title("Cryptographer1.0")
crypto_app.master.maxsize(750, 530)
crypto_app.master.protocol("WM_DELETE_WINDOW", quitApp)
crypto_app.mainloop()
# root.geometry("550x340")
