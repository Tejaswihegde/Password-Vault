import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
from PyQt5.sip import delete
import pyperclip
import re

with sqlite3.connect("password_manager.db") as db:
    cursor=db.cursor()

#=========================================================================================================================#
cursor.execute('''
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY ,
password TEXT NOT NULL);
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY ,
website TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL);
''')


#=========================================================================================================================#

#createpopup
def popUp(text):
    answer=simpledialog.askstring("Input string", text)
    return answer

#=========================================================================================================================#



#initiate wndow
window=Tk()
window.title("Password Manager")


#=========================================================================================================================#


#BUTTONS


add_btn=PhotoImage(file='addnew.png')
delete_btn=PhotoImage(file='delete.png')
save_btn=PhotoImage(file='save.png')
login_btn=PhotoImage(file='login.png')
reset_btn=PhotoImage(file='reset.png')
next_btn=PhotoImage(file='next.png')
check_btn=PhotoImage(file='check.png')
copy_btn=PhotoImage(file='copy.png')
back_btn=PhotoImage(file='back.png')


#bg_img=PhotoImage(file='angryimg.png')
#=========================================================================================================================#


#IMAGES


createmasterpassword=PhotoImage(file='create-master-password.png')
reentermasterpassword=PhotoImage(file='re-enter-master-password.png')


entermasterpassword=PhotoImage(file='enter-master-password.png')

password_img=PhotoImage(file='password.png')
password_manager=PhotoImage(file='password-manager.png')
username_img=PhotoImage(file='username.png')
website_img=PhotoImage(file='website.png')

enternewpassword=PhotoImage(file='enter-new-password.png')
enteroldpassword=PhotoImage(file='enter-old-password.png')
reenternewpassword=PhotoImage(file='re-enter-new-password.png')
passwordreset=PhotoImage(file='password-reset.png')






#=========================================================================================================================#



def hashPassword(input):
    hash=hashlib.md5(input)
    hash=hash.hexdigest()
    return hash



#=========================================================================================================================#



def firstScreen():
    window.geometry("600x600")
    lbl=Label(window,  image=createmasterpassword)
    #text="Create Master Password",
    lbl.config(anchor=CENTER)
    lbl.pack(pady=20)

    txt=Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl3=Label(window)
    lbl3.pack(pady=5)

    '''lowerReg=re.compile(r'[a-z]*')
    upperReg=re.compile(r'[A-Z]*')
    digitReg=re.compile(r'\d*')'''
    passwordEx=re.compile(r'''(
    ^(?=.*[A-Z])
    (?=.*[0-9])
    (?=.*[!@#$&*])
    (?=.*[a-z])
    .{8,}
    $
)''', re.VERBOSE)
    def checkpassword2():
        is_strong=passwordEx.search(txt.get())
        if (not is_strong):
            txt.delete(0, 'end')
            lbl3.config(text="Password too Weak, Try again")
        else:
            lbl3.config(text="")
            lbl1=Label(window,  image=reentermasterpassword)
            #text="Re-Enter Master password",
            lbl1.pack(pady=20)

            txt1=Entry(window, width=20, show="*")
            txt1.pack()
            txt1.focus()
            def savePassword():
                if txt.get()==txt1.get():
                    hashedPassword=hashPassword(txt.get().encode('utf-8'))
                    insert_password=''' INSERT INTO masterpassword(password) VALUES(?) '''
                    cursor.execute(insert_password, [(hashedPassword)])
                    db.commit()
                    
                    passwordManager()
                else:
                    lbl2.config(text="Passwords do not match")
            btn=Button(window, image=save_btn,  borderwidth=0,command=savePassword)
            btn.pack(pady=40)
    btn=Button(window, image=check_btn,  borderwidth=0,command=checkpassword2)
    btn.pack(pady=10)
    lbl2=Label(window)
    lbl2.pack()
    #pady=5
    my_lbl=Label(window, text='')
    my_lbl.pack(pady=10)



#=========================================================================================================================#

   

def loginscreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("600x250")
    #window.configure(background='blue')
    #img_lbl=Label(image=bg)
    #img_lbl
    lbl=Label(window,  image=entermasterpassword)
    #text="Enter Master Password",
    lbl.config(anchor=CENTER)
    lbl.pack(pady=20)

    txt=Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1=Label(window)
    lbl1.pack(pady=5)

    def getMasterPassword():
        checkhashedPassword=hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND password=?", [(checkhashedPassword)])
        print(checkhashedPassword)
        return cursor.fetchall()

    def checkPassword():
        match=getMasterPassword()
        if match:
            passwordManager()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="wrong Password")


    

    btn=Button(window, image=login_btn, borderwidth=0, command=checkPassword)
    btn.pack(pady=7)

    btn1=Button(window, image=reset_btn, borderwidth=0, command=resetPassword)
    btn1.pack(pady=7)



#=========================================================================================================================#





def resetPassword():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("600x700")
    lbl=Label(window,  image=passwordreset)
    #text="Password Reset",
    lbl.config(anchor=CENTER)
    lbl.pack(pady=10)

    lbl=Label(window,  image=enteroldpassword)
    #text="Enter Old Master Password",
    lbl.pack(pady=20)

    txt=Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1=Label(window)
    lbl1.pack(pady=5)

    lbl2=Label(window)
    lbl2.pack(pady=5)

    def getMasterPassword():
        checkhashedPassword=hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND password=?", [(checkhashedPassword)])
        print(checkhashedPassword)
        #print(checkhashedPassword)
        return cursor.fetchall()

    def checkPassword():
        match=getMasterPassword()
    
        if match:
            lbl=Label(window,  image=enternewpassword)
            #text="Enter New Master Password",
            lbl.pack(pady=20)
            txt1=Entry(window, width=20, show="*")
            txt1.focus()
            txt1.pack(pady=10)
            lbl=Label(window, image=reenternewpassword)
            # text="Re-enter New Master Password",
            lbl.pack(pady=20)
            txt2=Entry(window, width=20, show="*")
            txt2.pack()

            def savePassword():
                if txt1.get()==txt2.get():
                    hashedPassword=hashPassword(txt1.get().encode('utf-8'))
                    insert_password='''UPDATE masterpassword SET password= ? WHERE id=1 '''
                    cursor.execute(insert_password, [(hashedPassword)])
                    db.commit()
                
                    loginscreen()
                else:
                    lbl2.config(text="Passwords do not match")
            
            btn=Button(window, image=save_btn,borderwidth=0, command=savePassword)
            btn.pack(pady=40)
        else:
            txt.delete(0, 'end')
            lbl1.config(text="wrong Password")

    def goback():
        loginscreen()
    btn1=Button(window, image=back_btn,borderwidth=0, command=goback)
    btn1.pack(pady=5)
    btn=Button(window, image=next_btn, borderwidth=0, command=checkPassword)
    btn.pack(pady=10)




#=========================================================================================================================#




def passwordManager():
    for widget in window.winfo_children():
        widget.destroy()
        def addEntry():
            text1="Website"
            text2="Username"
            text3="password"

            website=popUp(text1)
            username=popUp(text2)
            password=popUp(text3)
            copy1(password)

            insert_fields='''INSERT INTO vault(website, username, password) VALUES(?, ?,?) '''
            cursor.execute(insert_fields, (website, username, password))
            db.commit()
            
            passwordManager()
        def removeEntry(input):
            cursor.execute("DELETE FROM vault WHERE id= ?",(input, ) )
            db.commit()
            passwordManager()
       

    window.geometry("1350x500")
    
    lbl=Label(window,  image=password_manager)
    #text="Password Manager",
    lbl.grid(column=1)


    btn=Button(window, image=add_btn, borderwidth=0, command=addEntry)
    btn.grid(column=1, pady=10)
    #

    lbl=Label(window, image=website_img)
    # text="Website",
    lbl.grid(row=2, column=0, padx=80)
    lbl=Label(window,  image=username_img)
    #text="Username",
    lbl.grid(row=2, column=1, padx=80)
    lbl=Label(window, image=password_img)
    #   text="Password",
    lbl.grid(row=2, column=2, padx=80)

    def copy1(pass1):
                pyperclip.copy(pass1)

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i=0
        while True:
            cursor.execute("SELECT * FROM vault")
            array=cursor.fetchall()
            lbl1=Label(window, text=(array[i][1]), font=("Helvetica", 12))
            lbl1.grid(column=0, row=i+3)
            lbl2=Label(window, text=(array[i][2]), font=("Helvetica", 12))
            lbl2.grid(column=1, row=i+3)
            lbl3=Label(window, text=(array[i][3]), font=("Helvetica", 12))
            lbl3.grid(column=2, row=i+3)
            
            btn=Button(window, image=copy_btn,  borderwidth=0,command=partial(copy1, array[i][3]))
            btn.grid(column=4, row=i+3, pady=4 )
            
            btn=Button(window, image=delete_btn ,borderwidth=0 , command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i+3, pady=4, padx=20)
            i=i+1
            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall())<=1):
                break
                            

#=========================================================================================================================#




cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginscreen()
else:
    firstScreen()
window.mainloop()