from functools import partial
from tkinter import *
from tkinter import simpledialog
from tkinter import ttk
from tkinter import messagebox
import pyaes
import base64
import mysql.connector
import uuid


username = ""

#change the user and password here
db=mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
)

cursor=db.cursor()
create_db="""CREATE DATABASE IF NOT EXISTS passVault"""
cursor.execute(create_db)
cursor.execute("use passVault")
cursor.execute("""CREATE TABLE IF NOT EXISTS secretKey(id INTEGER PRIMARY KEY, skey TEXT NOT NULL)""")
cursor.execute("SELECT * FROM secretKey")
temp=cursor.fetchall()
if (temp):
    key = temp[0][1]
else:
    key = uuid.uuid4().hex  
    insert_key = """INSERT INTO secretKey (id,skey) VALUES (1,%s)"""
    cursor.execute(insert_key, [key])
    db.commit()


cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS encryptedPassword(
username VARCHAR(20) PRIMARY KEY,
userPassword TEXT NOT NULL)
""")

cursor.execute(""" 
CREATE TABLE IF NOT EXISTS vault(
username VARCHAR(20) NOT NULL,
platform TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL,
memo TEXT NULL,
FOREIGN KEY (username) REFERENCES encryptedPassword(username),
PRIMARY KEY (username,account(20),platform(20)))
""")



def encrypt(key, data):
    """returns the base64 encrpyted string, that is to be stored in database/or may be stored in database"""
    key=key.encode('utf-8') #converts to bytestring for pyaes
    aes=pyaes.AESModeOfOperationCTR(key)
    encrypted_data=aes.encrypt(data).decode('latin-1')
    return encrypted_data

def decrypt(key,data):
    """returns the decrypted string"""
    key=key.encode('utf-8')
    aes=pyaes.AESModeOfOperationCTR(key)
    decrypted_data=aes.decrypt(data).decode('latin-1')
    return decrypted_data

def resetUserPassword(username,password):
    cursor.execute("SELECT * FROM masterpassword")
    temp=cursor.fetchall()
    masterPassword=temp[0][1]
    decrypted_master=(decrypt(key,masterPassword))
    while(len(decrypted_master)<32):
        decrypted_master=decrypted_master+"0"    
    cursor.execute("SELECT * FROM encryptedPassword WHERE BINARY username=(%s)",(username,))
    temp=cursor.fetchall()
    
    if (temp):
        temp=temp[0][1]
        decrypted_password=decrypt(decrypted_master,temp)  

        while(len(decrypted_password)<32):
            decrypted_password=decrypted_password+"0"

        while(len(decrypted_password)<32):
            decrypted_password=decrypted_password+"0"
        # print(decrypted_password)
        cursor.execute("UPDATE encryptedPassword SET userPassword=(%s) WHERE BINARY username=(%s)",(encrypt(decrypted_master,password),username))
        db.commit()
        #get all passwords from vault
        
        # print(decrypted_master)
        # print(decrypted_password)
          
        cursor.execute("SELECT * FROM vault WHERE BINARY username=(%s)",[username])
        temp=cursor.fetchall()
        for i in temp:
            platform=i[1]
            account=i[2]
            password=i[3]
            # print(password)
            updatePassword(username,platform,account,decrypt(decrypted_password,password))
        return True
    else:
        return False

def checkAdminLogin(password):
    cursor.execute("SELECT * FROM masterpassword")
    temp=cursor.fetchall()
    masterPassword=temp[0][1]
    if(decrypt(key,masterPassword)==password):
        return True #ok, show admin screen
    else:
        return False

def checkUserAlreadyExist(username):
    cursor.execute("SELECT * FROM encryptedPassword WHERE BINARY username=(%s)",[username])
    temp=cursor.fetchall()
    if(temp):
        return True    #user already exists
    else:
        return False 

def createAccount(username,password):
    #insert user into database
    cursor.execute("SELECT * FROM masterpassword")
    temp=cursor.fetchall()
    masterPassword=temp[0][1]
    insert_user = """INSERT INTO encryptedPassword(username,userPassword) VALUES(%s,%s) """
    decrypted=(decrypt(key,masterPassword))
    while(len(decrypted)<32):
        decrypted=decrypted+"0"
    cursor.execute(insert_user, (username,encrypt(decrypted,password)))
    db.commit()
    return True

def addNewEntry(username,platform,account,userPassword,memo):
    #check if entry already exists where username and platform are primary key
    

    cursor.execute("SELECT * FROM vault WHERE BINARY username=(%s) AND platform=(%s) AND BINARY account=(%s)",(username,platform,account))
    temp=cursor.fetchall()
    if(temp):
        return 0
    elif(username=="" or platform=="" or account=="" or userPassword==""):
        return 1
    else:
        cursor.execute("SELECT * FROM masterpassword")
        temp=cursor.fetchall()
        masterPassword=temp[0][1]
        decrypted_master=(decrypt(key,masterPassword))
        while(len(decrypted_master)<32):
            decrypted_master=decrypted_master+"0"
        insert_user = """INSERT INTO vault(username,platform,account,password,memo)
        VALUES(%s,%s,%s,%s,%s) """
        #fetch the userpassword from encrypted password table
        cursor.execute("SELECT * FROM encryptedPassword WHERE BINARY username=(%s)",[username])
        temp=cursor.fetchall()
        mainuser=temp[0][1]
        mainuser=decrypt(decrypted_master,mainuser)
        while(len(mainuser)<32):
            mainuser=mainuser+"0"
        cursor.execute(insert_user, (username,platform,account,encrypt(mainuser,userPassword),memo))
        db.commit()
        return 2
        
def deleteEntry(username,platform,account):
    cursor.execute("DELETE FROM vault WHERE BINARY username=(%s) AND platform=(%s) AND BINARY account=(%s)",[username,platform,account])
    db.commit()
    
def updatePassword(username,platform,account,password):
    cursor.execute("SELECT * FROM encryptedPassword WHERE BINARY username=(%s)",[username])
    temp=cursor.fetchall()
    if (temp):
        cursor.execute("SELECT * FROM masterpassword")
        temp=cursor.fetchall()
        masterPassword=temp[0][1]
        decrypted_master=(decrypt(key,masterPassword))
        while(len(decrypted_master)<32):
            decrypted_master=decrypted_master+"0"
        #get user password
        cursor.execute("SELECT * FROM encryptedPassword WHERE BINARY username=(%s)",[username])
        temp=cursor.fetchall()
        mainuser=temp[0][1]
        mainuser=decrypt(decrypted_master,mainuser)
        while(len(mainuser)<32):
            mainuser=mainuser+"0"
        cursor.execute("UPDATE vault SET password=(%s) WHERE BINARY username=(%s) and platform=(%s) and BINARY account=(%s)",[encrypt(mainuser,password),username,platform,account])
        db.commit()
        return True
    else:
        return False

def checkLogin(username,password):
    cursor.execute("SELECT * FROM encryptedPassword WHERE BINARY username=(%s)",[username])
    temp=cursor.fetchall()
    if (temp):
        #select master password from database
        temp_pw=temp[0][1]
        cursor.execute("SELECT * FROM masterpassword")
        temp=cursor.fetchall()
        masterPassword=temp[0][1]
        decrypted_master=decrypt(key,masterPassword)
        while(len(decrypted_master)<32):
            decrypted_master=decrypted_master+"0"
        
        if(decrypt(decrypted_master,temp_pw)==password):
            return True
        else:
            return False
    else:
        return False

def popUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer


window = Tk()
window.update()
window.configure(bg='#292841')
window.title("Password Vault & Manager")


def Launch():
        
    window.geometry("300x200")
    window.resizable(False, False)
    lbl = Label(window, text="Create Admin Account")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER, font=("Arial", 16))
    lbl.pack(padx=6,pady=4)
    lb2 = Label(window, text="Enter Master Password")
    lb2.configure(bg='#292841',fg='white')
    lb2.config(anchor=CENTER)
    lb2.pack(padx=6,pady=4)
    txt = Entry(window, width=20, show="*")
    txt.pack(padx=6,pady=(2, 5))
    txt.focus()
    lbl1 = Label(window, text="Re-enter Password")
    lbl1.configure(bg='#292841', fg='white')
    lbl1.config(anchor=CENTER)
    lbl1.pack(padx=6,pady=(5,2))
    txt1 = Entry(window, width=20, show="*")
    txt1.pack(padx=6,pady=(2,5))

    def createAdminAccount():
        if txt.get() == txt1.get():
            password=txt.get()
            insert_user = """INSERT INTO masterpassword(id,password) VALUES(1,%s);"""
            cursor.execute(insert_user, [encrypt(key,password)])
            db.commit()
            for widget in window.winfo_children():
                widget.destroy()
            loginScreen()
        else:
            lbl.config(text="Passwords don't match")

    btn = Button(window, text="Save", command=createAdminAccount)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)

def signUp():
    
    window.geometry("300x250")
    window.resizable(False, False)
    lbl = Label(window, text="Sign up to PASSWORD vault & Manager",font=("Arial", 13))
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    lbl = Label(window, text="Username")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt1 = Entry(window, width=20)
    txt1.pack(pady=(2, 5))
    lb2 = Label(window, text="Password")
    lb2.configure(bg='#292841',fg='white')
    lb2.config(anchor=CENTER)
    lb2.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack(pady=(2, 5))
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.configure(bg='#292841', fg='white')
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt2 = Entry(window, width=20, show="*")
    txt2.pack(pady=(2, 5))

    def signup():
        if(checkUserAlreadyExist(txt1.get())):
            messagebox.showerror("Error", "User already exists")
        elif(len(txt1.get())==0 and len(txt.get())==0):
            messagebox.showerror("Error", "Username and Password cannot be empty")
        elif(txt.get()!=txt2.get()):
            messagebox.showerror("Error", "Passwords don't match")
        elif(txt.get()==txt2.get()):
            createAccount(txt1.get(),txt.get())
            messagebox.showinfo("Success", "Account created")
            for widget in window.winfo_children():
                widget.destroy()
            loginScreen()


    btn = Button(window, text="Create Account",command=signup)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=(1, 9))

    def back():
        for widget in window.winfo_children():
            widget.destroy()
        loginScreen()

    btn = Button(window, text="BACK")
    btn.configure(bg="#308B3B", fg='white',command=back)
    btn.pack(side=BOTTOM)



def loginScreen():
    window.resizable(False, False)
    window.geometry("300x200")
    lbl = Label(window, text="LOGIN TO PASSWORD vault & Manager")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    lbl = Label(window, text="Username")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt1 = Entry(window, width=20)
    txt1.pack()
    lb2 = Label(window, text="Password")
    lb2.configure(bg='#292841',fg='white')
    lb2.config(anchor=CENTER)
    lb2.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    def goToNewUser():
        for widget in window.winfo_children():
            widget.destroy()
        signUp()

    def goToAdminScreen():
        for widget in window.winfo_children():
            widget.destroy()
        adminLogin()

    def login():
        if(checkLogin(txt1.get(),txt.get())):
            username=txt1.get()
            for widget in window.winfo_children():
                widget.destroy()
            vaultScreen(username)
        else:
            messagebox.showerror("Error", "Incorrect username or password")

    btn = Button(window, text="LOGIN", command=login)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)
    button4=Button(window, text="ADMIN?", command=goToAdminScreen)
    button4.configure(bg="#308B3B", fg='white')
    button4.pack(side=LEFT)
    button4=Button(window, text="New User?",command=goToNewUser)
    button4.configure(bg="#308B3B", fg='white')
    button4.pack(side=RIGHT)

def adminLogin():

    window.resizable(False, 
    False)
    window.geometry("300x200")
    lbl = Label(window, text="Enter ADMIN Password")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def checkLogin():
        if(checkAdminLogin(txt1.get())):
            for widget in window.winfo_children():
                widget.destroy()
            adminDashboard()
        else:
            messagebox.showerror("Error", "Incorrect password")

    def back():
        for widget in window.winfo_children():
            widget.destroy()
        loginScreen()
    btn2 = Button(window, text="BACK", command=back)
    btn2.configure(bg="#308B3B", fg='white')
    btn2.pack(side=BOTTOM)
    btn = Button(window, text="LOGIN",command=checkLogin)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)
    

def adminDashboard():

    window.resizable(False, False)
    window.geometry("300x200")
    lbl = Label(window, text="ADMIN DASHBOARD")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    
    def goToReset():
        for widget in window.winfo_children():
            widget.destroy()
        ResetUser()

    def accessPW():
        for widget in window.winfo_children():
            widget.destroy()
        AccessVault()
    def back():
        for widget in window.winfo_children():
            widget.destroy()
        loginScreen()

    btn = Button(window, text="Access Password Vault",command=accessPW)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)
    btn = Button(window, text="Reset User",command=goToReset)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)
    btn2 = Button(window, text="LOGOUT",command=back)
    btn2.configure(bg="#308B3B", fg='white')
    btn2.pack(side=BOTTOM)
    
def AccessVault():
    window.resizable(False, False)
    window.geometry("300x200")
    lb2 = Label(window, text="Enter UserName to access their vault")
    lb2.configure(bg='#292841',fg='white')
    lb2.config(anchor=CENTER)
    lb2.pack()
    lbl = Label(window, text="Username")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt1 = Entry(window, width=20)
    txt1.pack()

    def back():
        for widget in window.winfo_children():
            widget.destroy()
        adminDashboard()

    btn2 = Button(window, text="BACK", command=back)
    btn2.configure(bg="#308B3B", fg='white')
    btn2.pack(side=BOTTOM)

    def accessVault():
        if(checkUserAlreadyExist(txt1.get())):
            username=txt1.get()
            for widget in window.winfo_children():
                widget.destroy()
            vaultScreen(username)
        else:
            messagebox.showerror("Error", "Username does not exist")

    btn = Button(window, text="Search",command=accessVault)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)
    
def ResetUser():
    window.resizable(False, False)
    window.geometry("300x200")
    lbl = Label(window, text="Username")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt1 = Entry(window, width=20)
    txt1.pack()

    lb2 = Label(window, text="New Password")
    lb2.configure(bg='#292841',fg='white')
    lb2.config(anchor=CENTER)
    lb2.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    
    def back():
        for widget in window.winfo_children():
            widget.destroy()
        adminDashboard()

    btn2 = Button(window, text="BACK", command=back)
    btn2.configure(bg="#308B3B", fg='white')
    btn2.pack(side=BOTTOM)


    def resetLogic():
        if(resetUserPassword(txt1.get(),txt.get())):
            messagebox.showinfo("Success", "Password Reset")
            for widget in window.winfo_children():
                widget.destroy()
            loginScreen()
        else:
            messagebox.showerror("Error", "User does not exist")
        
    btn = Button(window, text="Reset User",command=resetLogic)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack(pady=5)

def entryaddition(username):
    window.geometry("400x400")
    window.resizable(False, False)
    z = Label(window ,text = "Entry Addition",font=('Arial',16))
    z.grid(row = 0 , column = 1)
    a = Label(window ,text = "Platform name")
    a.grid(row = 1 , column = 0)
    b = Label(window ,text = "Platform Username")
    b.grid(row = 2 , column = 0)
    c = Label(window ,text = "Platform Password")
    c.grid(row = 3 , column = 0)
    d = Label(window ,text = "Memo")
    d.grid(row = 4,column = 0)
    z.configure(bg='#292841',fg='white')
    a.configure(bg='#292841',fg='white')
    b.configure(bg='#292841',fg='white')
    c.configure(bg='#292841',fg='white')
    d.configure(bg='#292841',fg='white')
    a1 = Entry(window)
    a1.grid(row = 1,column = 1,pady=5)
    b1 = Entry(window)
    b1.grid(row = 2,column = 1,pady=5)
    c1 = Entry(window,show="*")
    c1.grid(row = 3,column = 1,pady=5)
    t = Text(window,height=10,width=20)
    t.grid(row =4,column = 1,pady=5)
    def addNewEntryCall():
        if(addNewEntry(username,a1.get(),b1.get(),c1.get(),t.get("1.0",END))==2):
            messagebox.showinfo("Success", "Entry Added")
            for widget in window.winfo_children():
                widget.destroy()
            vaultScreen(username)
        elif(addNewEntry(username,a1.get(),b1.get(),c1.get(),t.get("1.0",END))==1):
            messagebox.showerror("Error", "Invalid Entry")
        elif(addNewEntry(username,a1.get(),b1.get(),c1.get(),t.get("1.0",END))==0):
            messagebox.showerror("Error", "Entry already exists")

    def cancel_add_entry():
        for widget in window.winfo_children():
            widget.destroy()
        print("OK")
        vaultScreen(username)
    
    btn = Button(window, text="Add",command=addNewEntryCall)
    btn.grid(row=5,column=1)
    btn.configure(bg="#308B3B", fg='white')
    btn = Button(window, text="Cancel Entry",command=cancel_add_entry)
    btn.grid(row=6,column=1)
    btn.configure(bg="#308B3B", fg='white')

def addmemo(username,account,platform):
    window.geometry("600x450")
    lbl = Label(window, text="Memo")
    lbl.configure(bg='#292841',fg='white')
    lbl.config(anchor=CENTER, font=("Arial", 16))
    lbl.pack(padx=6,pady=4)
    txt1 = Text(window, width=40,height=20)
    #set text to the database entry
    cursor.execute("SELECT memo FROM vault WHERE BINARY username = (%s) and BINARY account = (%s) and platform = (%s)",(username,account,platform))
    memo = cursor.fetchone()
    txt1.insert(END,memo[0])
    txt1.pack()
    def memoInsert():
        cursor.execute("UPDATE vault SET memo = (%s) WHERE username = (%s) and account = (%s) and platform = (%s)",(txt1.get("1.0",END),username,account,platform))
        db.commit()
        messagebox.showinfo("Success", "Memo Updated")
        for widget in window.winfo_children():
            widget.destroy()
        vaultScreen(username)

    btn = Button(window, text="Update",height=2,width=10,command=memoInsert)
    btn.configure(bg="#308B3B", fg='white')
    btn.pack()
    btn.pack(pady=(10, 5))

def vaultScreen(username):

    def addEntry():
        for widget in window.winfo_children():
            widget.destroy()
        entryaddition(username)

    def updateEntry(username,platform,account):
        update = "Type new password"
        password = popUp(update)

        if(updatePassword(username,platform,account,password)):
            messagebox.showinfo("Success", "Password Updated")
            for widget in window.winfo_children():
                widget.destroy()
            vaultScreen(username)
        else:
            messagebox.showerror("Error", "Invalid Entry")

        for widget in window.winfo_children():
            widget.destroy()
        vaultScreen(username)

    def removeEntry(platform, account):
        deleteEntry(username,platform,account)   
        messagebox.showinfo("Success", "Entry Removed")
        for widget in window.winfo_children():
            widget.destroy()
        vaultScreen(username)
            

    def copyAcc(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def copyPass(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def addMemo(platform,account):
        for widget in window.winfo_children():
            widget.destroy()
        addmemo(username,account,platform)
        window.clipboard_clear()

    def logout():
        for widget in window.winfo_children():
            widget.destroy()
        loginScreen()

    window.geometry("700x350")
    main_frame = Frame(window)
    main_frame.configure(bg='#292841')
    main_frame.pack(fill=BOTH, expand=1)

    my_canvas = Canvas(main_frame)
    my_canvas.configure(bg='#292841')
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    second_frame = Frame(my_canvas)
    second_frame.configure(bg='#292841')
    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")


    lbl = Label(second_frame, text="Password Vault",font=(30))
    lbl.grid(column=2)
    lbl.configure(bg="#292841", fg='white')
    btn0=Button(second_frame, text="Logout",command=logout)
    btn0.grid(column=2,pady=10,padx=5)
    btn0.configure(bg="#308B3B", fg='white')
    btn = Button(second_frame, text="Store New", command=addEntry)
    btn.grid(column=4, pady=10)
    btn.configure(bg="#308B3B", fg='white')
    lbl = Label(second_frame, text="Platform")
    lbl.grid(row=2, column=0, padx=40)
    lbl.configure(bg="#292841", fg='white')
    lbl = Label(second_frame, text="Account")
    lbl.grid(row=2, column=1, padx=40)
    lbl.configure(bg="#292841", fg='white')
    lbl = Label(second_frame, text="Password")
    lbl.grid(row=2, column=2, padx=40)
    lbl.configure(bg="#292841", fg='white')

    cursor.execute("SELECT * FROM vault where BINARY username=(%s)", [username])
    if cursor.fetchall() is not None:
        i = 0
        cursor.execute("SELECT * FROM masterpassword")
        temp=cursor.fetchall()
        tempormaster=temp[0][1]
        tempormaster = decrypt(key,tempormaster)
        while(len(tempormaster)<32):
            tempormaster=tempormaster+"0"
        
        #get user password from encrypted password
        cursor.execute("SELECT * FROM encryptedPassword where BINARY username=(%s)", (username,))
        encryptedPassword=cursor.fetchall()
        encryptedPassword=encryptedPassword[0][1]
        decrypted_password=decrypt(tempormaster,encryptedPassword)
        
        while(len(decrypted_password)<32):
            decrypted_password=decrypted_password+"0"
        
        while True:
            cursor.execute("SELECT * FROM vault where BINARY username=(%s)", (username,))
            array=cursor.fetchall()
            #get master password
           
            lbl1 = Label(second_frame, text=(array[i][1]))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(second_frame, text=(array[i][2]))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(second_frame, text=(decrypt(decrypted_password,array[i][3])))
            lbl3.grid(column=2, row=i + 3)
            btn2 = Button(second_frame, text="Copy Acc", command=partial(copyAcc, array[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn2.configure(bg="#308B3B", fg='white')
            btn3 = Button(second_frame, text="Copy Pass", command=partial(copyPass, decrypt(decrypted_password,array[i][3])))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn3.configure(bg="#308B3B", fg='white')
            btn1 = Button(second_frame, text="Update", command=partial(updateEntry, username=username, platform=array[i][1], account=array[i][2]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn1.configure(bg="#308B3B", fg='white')
            btn = Button(second_frame, text="Delete", command=partial(removeEntry, array[i][1],array[i][2]))
            btn.grid(column=6, row=i + 3, pady=10)
            btn.configure(bg="#308B3B", fg='white')
            btn = Button(second_frame, text="Memo", command=partial(addMemo, platform=array[i][1], account=array[i][2]))
            btn.grid(column=7, row=i + 3, pady=10)
            btn.configure(bg="#308B3B", fg='white')

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():    
    loginScreen()
else:
    Launch()
window.mainloop()
