# ICS483 Group Project
# Authors: Kekeli D Akouete, Vang Uni A
# Implementing encryption in an application

from tkinter import filedialog
from tkinter import *
from tkinter import messagebox
import os
from MyCipher import MyCipher


# Callbacks to entry fields
def key_callback(event):
    ivEntry.focus_set()


def file_callback(event):
    keyEntry.focus_set()


def iv_callback(event):
    outputText.focus_set()


# Clear the input fields
def clear_callback():
    filename.set("")
    keyString.set("")
    ivTf.set("")
    outputResult.set("")
    fileEntry.focus_set()


# Save function to write to a file
def saveAs():
    # Save your work to a file
    fname = filedialog.asksaveasfilename()
    if fname != '':
        writefile(outputResult.get(), fname)


# Save keys function
def saveKey():
    if keyString.get() != '' or ivTf.get() != '':
        # Save your keys to a file
        fname = filedialog.asksaveasfilename()
        if fname:
            # Saving your key and IV to a file of your choice
            keys = "Key={} \nIV={}".format(keyString.get(), ivTf.get())
            writefile(keys, fname)


# Display the help menu for instruction
def showhelp():
    # Instruction on how to use the application
    messagebox.showinfo(title="About", message=readfile("help.txt"))


# Prompt to browse a file directory
def openfile():
    if keyString.get() != '' or ivTf.get() != '':
        answer = messagebox.askyesno("Save Work", "Do you want to save your work?")
        if answer:
            saveAs()
        else:
            # Clear the variables values
            filename.set("")
            keyString.set("")
            ivTf.set("")
            outputResult.set("")
            openfile()
    else:
        # open the dialog widget
        myFile = filedialog.askopenfilename()
        if myFile:
            filename.set(myFile)
            keyEntry.focus_set()
        else:
            fileEntry.focus_set()


# Definition of the read method which takes a file
def readfile(file):
    if os.path.exists(file):
        with open(file, "r") as fd:
            file_content = fd.read()
            return file_content
    else:
        return "File not found"


# Definition of the write method
def writefile(context, file):
    if type(context) == bytes:
        context.decode()
    with open(file, "w") as fd:
        fd.write(context)
        fd.seek(0)


# Action to perform when user click generate key
def generate_key_callback():
    mykey = cipher.keygen()
    keyString.set(mykey)


# Action to perform when user click encrypt button
def encrypt_callback():
    if filename.get() == '':
        # Request the input file
        messagebox.showinfo(title="Error", message="Please Select a Valid File Path!")
        fileEntry.focus_set()
    elif keyString.get() == "" or len(keyString.get()) < 16:
        # Validate the key and key length
        messagebox.showinfo(title="Error", message="Please Enter a valid Key!")
        keyEntry.focus_set()
    elif len(readfile(filename.get())) == 14:
        # Validate the input file path
        messagebox.showinfo(title="Error", message="File Not Found!")
        fileEntry.focus_set()
    else:
        # Encryption process
        plaintext = readfile(filename.get())
        c = cipher.encryptAES_128(plaintext, keyString.get())
        ivTf.set(c[0])
        outputResult.set(c[1])


# Action to perform when user click decrypt button
def decrypt_callback():
    if filename.get() == '':
        messagebox.showinfo(title="Error", message="Please Select an Input first!")
        fileEntry.focus_set()
    elif outputResult.get() != '':
        plnText = cipher.decryptAES_128(keyString.get(), ivTf.get(), outputResult.get())
        if plnText != "Wrong key or IV provided":
            outputResult.set(plnText)
        else:
            messagebox.showinfo(title="Error", message=plnText)
            keyEntry.focus_set()
    else:
        plnText = cipher.decryptAES_128(keyString.get(), ivTf.get(), readfile(filename.get()))
        if plnText == "Wrong key or IV provided":
            messagebox.showinfo(title="Error", message=plnText)
            keyEntry.focus_set()
        else:
            outputResult.set(plnText)


# Custom window class definition
class Window(Frame):
    def __init__(self, master=None):
        super().__init__()
        self.master = master
        menu = Menu(self.master)
        self.master.config(menu=menu)

        # Menu bar items
        fileMenu = Menu(menu)
        menu.add_cascade(label="File", menu=fileMenu)
        fileMenu.add_command(label="Open", command=openfile)
        fileMenu.add_command(label="Save As", command=saveAs)
        fileMenu.add_command(label="Save Keys", command=saveKey)
        fileMenu.add_command(label="Exit", command=quitApp)

        actionMenu = Menu(menu)
        menu.add_cascade(label="Action", menu=actionMenu)
        actionMenu.add_command(label="Decrypt", command=decrypt_callback)
        actionMenu.add_command(label="Encrypt", command=encrypt_callback)
        actionMenu.add_command(label="Generate key", command=generate_key_callback)

        helpMenu = Menu(menu)
        menu.add_cascade(label="Help", menu=helpMenu)
        helpMenu.add_command(label="About", command=showhelp)


# Exit method definition
def quitApp():
    if messagebox.askokcancel("Confirm Exit", "Do you really wish to quit?"):
        root.destroy()


root = Tk()
cipher = MyCipher()
crypto_app = Window(root)
crypto_app.master.title("Cryptographer1.0")
root.geometry("650x350")
crypto_app.master.maxsize(750, 530)
crypto_app.master.protocol("WM_DELETE_WINDOW", quitApp)

# File entry input widget definition
frame1 = Frame()
frame1.pack(fill=X)
fileLabel = Label(frame1, text="Input File:", width=9)
fileLabel.pack(side=LEFT, padx=5, pady=5)
filename = StringVar()
fileEntry = Entry(frame1, textvariable=filename)
fileEntry.bind("<Return>", file_callback)
fileEntry.pack(fill=X, padx=5, expand=True)

# Key entry input widget definition
frame2 = Frame()
frame2.pack(fill=X)
keyLabel = Label(frame2, text="Key:", width=9)
keyLabel.pack(side=LEFT, padx=5, pady=5)
keyString = StringVar()
keyEntry = Entry(frame2, textvariable=keyString)
keyEntry.bind("<Return>", key_callback)
keyEntry.pack(fill=X, padx=5, expand=True)

# IV entry input widget definition
frame3 = Frame()
frame3.pack(fill=X)
ivLabel = Label(frame3, text="IV:", width=9)
ivLabel.pack(side=LEFT, padx=5, pady=5)
ivTf = StringVar()
ivEntry = Entry(frame3, textvariable=ivTf)
ivEntry.bind("<Return>", iv_callback)
ivEntry.pack(fill=X, padx=5, expand=True)

# Output widget definition
frame4 = Frame()
frame4.pack(fill=X)
outputLabel = Label(frame4, text="Output:", width=9)
outputLabel.pack(side=LEFT, padx=5, pady=5)
outputResult = StringVar()
outputText = Label(frame4, textvariable=outputResult)
outputText.pack(fill=X, padx=5, pady=5, expand=True)

#  Buttons widget definition
frame5 = Frame(relief=RAISED, borderwidth=0)
frame5.pack(fill=BOTH, expand=True)
clearButton = Button(frame5, text="Clear", command=clear_callback)
clearButton.pack(side=RIGHT, padx=5)
decryptButton = Button(frame5, text="Decrypt", command=decrypt_callback)
decryptButton.pack(side=RIGHT, padx=5, pady=5)
encryptButton = Button(frame5, text="Encrypt", command=encrypt_callback)
encryptButton.pack(side=RIGHT, padx=5)

# the application footer note
status = Label(root, text="Cryptographer_1.0 \u00AE All rights reserved", justify=CENTER)
status.pack(side=BOTTOM, padx=5, pady=5, anchor=S)
crypto_app.mainloop()

######################### Test codes ##############################
# print("Key: " + keyString.get() + "\n", "IV: " + ivTf.get())
# print("Content: " + readfile(filename.get()))
# keyTf = bytearray()
# print("Content: " + plnText)
# keyTf.extend(mykey)
# keyString.set(mykey.hex().upper())
# print("IV: " + c[0] + "\n", "Cipher Text: " + c[1])

