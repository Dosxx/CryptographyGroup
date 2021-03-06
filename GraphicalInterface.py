# ICS483 Group Project
# Authors: Kekeli D Akouete, Vang Uni A
# Implementing encryption in an application
import io
from base64 import b64decode
from tkinter import filedialog
from tkinter import *
from tkinter import messagebox
import os
from MyCipher import MyCipher
from PIL import Image, ImageTk


# Callbacks to entry fields
def key_callback(event):
    ivEntry.focus_set()


def file_callback(event):
    keyEntry.focus_set()


def iv_callback(event):
    display.focus_set()


# Clear the input fields
def clear_callback():
    filename.set("")
    keyString.set("")
    ivTf.set("")
    display.delete(1.0, END)
    fileEntry.focus_set()


# Save function to write to a file
def saveAs():
    # Save your work to a file
    fname = filedialog.asksaveasfilename()
    if fname != '':
        writefile(display.get(1.0, END), fname)


# Save keys function
def saveKey():
    if keyString.get() != '' or ivTf.get() != '':
        # Save your keys to a file
        fname = filedialog.asksaveasfilename()
        if fname:
            # Saving your key and IV to a file of your choice
            keys = "Key {} \nIV {}".format(keyString.get(), ivTf.get())
            writefile(keys, fname)


# Import saved keys from a file
def import_key():
    keys = {}
    keyFile = filedialog.askopenfilename()
    if keyFile:
        with open(keyFile) as fd:
            for line in fd:
                (key, val) = line.split()
                keys[key] = val
        keyString.set(keys.get("Key"))
        ivTf.set(keys.get("IV"))


# Display the help menu for instruction
def showhelp():
    # Instruction on how to use the application
    messagebox.showinfo(title="About", message=readfile("help.txt"))


# Check if the file is an image
def is_jpg(content):
    try:
        image = Image.open(io.BytesIO(content))
        return image.format == "JPEG"
    except IOError:
        return False


# Prompt to browse a file directory
def openfile():
    if keyString.get() != '' or ivTf.get() != '':
        answer = messagebox.askyesno("Save Work", "Do you want to save your work?")
        if answer:
            saveAs()
        else:
            # Clear the variables values
            clear_callback()
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
    if file.__contains__(".txt"):
        # Read a text file mode
        with open(file, "rb") as fd:
            file_content = fd.read()
            return file_content
    elif file.__contains__(".jpeg") or file.__contains__(".jpg"):
        # Read image file mode
        try:
            with Image.open(file) as im:
                buffer = io.BytesIO()
                im.save(buffer, format='JPEG')
                byte_image = buffer.getvalue()
            return byte_image
        except IOError:
            messagebox.showerror(title="Error", message="Could not read the Image")
            pass


# Definition of the write method
def writefile(context, file):
    if type(context) == bytes:
        context = b64decode(context)
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
        messagebox.showerror(title="Error", message="Please Select a Valid File Path!")
        fileEntry.focus_set()
    elif not os.path.exists(filename.get()):
        # Validate the input file path
        messagebox.showerror(title="Error", message="File Not Found!")
        fileEntry.focus_set()
    elif len(keyString.get()) < 24:
        # Validate the key and key length
        messagebox.showerror(title="Error", message="Please Enter a valid Key!")
        keyEntry.focus_set()
    elif filename.get().__contains__(".txt") and len(readfile(filename.get())) == 0:
        messagebox.showerror(title="Error", message="File is Empty")
        fileEntry.focus_set()
    else:
        # Encryption process
        plaintext = readfile(filename.get())
        c = cipher.encryptAES_128(plaintext, keyString.get())
        ivTf.set(c[0])
        display.delete(1.0, END)
        display.insert(INSERT, c[1])


# Action to perform when user click decrypt button
def decrypt_callback():
    if filename.get() == '':
        messagebox.showerror(title="Error", message="Please Select an Input first!")
        fileEntry.focus_set()
    elif len(display.get(1.0, END)) > 1:
        plnText = cipher.decryptAES_128(keyString.get(), ivTf.get(), display.get(1.0, END))
        if plnText == "Wrong key or IV provided" or plnText == "Incorrect Encoding":
            messagebox.showerror(title="Error", message=plnText)
            keyEntry.focus_set()
        else:
            render_output(plnText)
    elif keyString.get() != '' and ivTf.get() != '':
        plnText = cipher.decryptAES_128(keyString.get(), ivTf.get(), readfile(filename.get()))
        if plnText == "Wrong key or IV provided":
            messagebox.showerror(title="Error", message=plnText)
            keyEntry.focus_set()
        else:
            render_output(plnText)
    else:
        messagebox.showerror(title="Error", message="Please Provide a key and an IV!")
        keyEntry.focus_set()


def render_output(plnText):
    if is_jpg(plnText):
        photo = ImageTk.PhotoImage(Image.open(io.BytesIO(plnText)))
        display.delete(1.0, END)
        display.image_create(INSERT, image=photo)
        display.image = photo
    else:
        display.delete(1.0, END)
        display.insert(INSERT, plnText)


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
        fileMenu.add_command(label="Import Keys", command=import_key)
        fileMenu.add_command(label="Exit", command=quitApp)

        actionMenu = Menu(menu)
        menu.add_cascade(label="Action", menu=actionMenu)
        actionMenu.add_command(label="Decrypt", command=decrypt_callback)
        actionMenu.add_command(label="Encrypt", command=encrypt_callback)
        actionMenu.add_command(label="Generate key", command=generate_key_callback)
        actionMenu.add_command(label="Clear", command=clear_callback)

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
root.geometry("750x650")
crypto_app.master.protocol("WM_DELETE_WINDOW", quitApp)

# File entry input widget definition
frame1 = Frame()
frame1.pack(fill=X)
fileLabel = Label(frame1, text="Input File:", width=9)
fileLabel.pack(side=LEFT, padx=5, pady=5)
filename = StringVar()
fileEntry = Entry(frame1, textvariable=filename)
fileEntry.bind("<Return>", file_callback)
fileEntry.pack(anchor=W, fill=X, padx=25, expand=True)

# Key entry input widget definition
frame2 = Frame()
frame2.pack(fill=X)
keygenButton = Button(frame2, text="Key/gen", command=generate_key_callback)
keygenButton.pack(side=LEFT, padx=12, pady=5)
keyString = StringVar()
keyEntry = Entry(frame2, textvariable=keyString)
keyEntry.bind("<Return>", key_callback)
keyEntry.pack(fill=X, padx=25, expand=True)

# IV entry input widget definition
frame3 = Frame()
frame3.pack(fill=X)
ivLabel = Label(frame3, text="IV:", width=9)
ivLabel.pack(side=LEFT, padx=5, pady=5)
ivTf = StringVar()
ivEntry = Entry(frame3, textvariable=ivTf)
ivEntry.bind("<Return>", iv_callback)
ivEntry.pack(fill=X, padx=25, expand=True)
frameD = Frame()
displayLabel = Label(frameD, text="OUTPUT", anchor=CENTER)
displayLabel.pack()
frameD.pack(fill=X, expand=FALSE)
# Display widget definition
frame4 = Frame(bd=2, relief=SUNKEN)
frame4.grid_rowconfigure(0, weight=1)
frame4.grid_columnconfigure(0, weight=1)
yScrollbar = Scrollbar(frame4)
yScrollbar.grid(row=0, column=1, sticky=N+S)
display = Text(frame4, wrap=WORD, bd=0, yscrollcommand=yScrollbar.set,
               foreground="white", background="black")
display.grid(row=0, column=0, sticky=N+S+E+W)
yScrollbar.config(command=display.yview)
frame4.pack(fill=X, padx=25, expand=FALSE)

# Buttons widget definition
frame5 = Frame(relief=RAISED, borderwidth=0)
frame5.pack(fill=BOTH, expand=True)
clearButton = Button(frame5, text="Clear", command=clear_callback)
clearButton.pack(side=RIGHT, padx=20)
decryptButton = Button(frame5, text="Decrypt", command=decrypt_callback)
decryptButton.pack(side=RIGHT, padx=15)
encryptButton = Button(frame5, text="Encrypt", command=encrypt_callback)
encryptButton.pack(side=RIGHT, padx=15)

# the application footer note
status = Label(root, text="Cryptographer_1.0 \u00AE All rights reserved", justify=CENTER)
status.pack(side=BOTTOM, padx=5, pady=5, anchor=S)
crypto_app.mainloop()
