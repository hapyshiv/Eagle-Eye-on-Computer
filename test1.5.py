import psutil
from win32com.client import GetObject
import os
import wmi
from Tkinter import *
import ttk
import time
import threading
import pythoncom
from pcapy import findalldevs, open_live
import pcapy
from impacket import ImpactDecoder, ImpactPacket
root=Tk()
#root=Tk(width=200,length=200)
root.geometry('1320x670+10+10')
root.title("Project:Eagle Eye on Computer by Shivraj Singh")
os.system('cls')
#default interface is first interface
choice=0
lb1=Listbox(root)
lb2=Listbox(root)
lb3=Listbox(root)
lb4=Listbox(root)
lb5=Listbox(root)
lb6=Listbox(root)
#t=Text(root)
#t.pack()
def process_detail():
    print "**************************Running Process************************"
    lbl1=Label(root,text="Process Detail",font="Times 15 bold",fg="black").place(x=220,y=110)
    lb1.place(x=220,y=140,width=180,height=300)
    c=wmi.WMI()
    for p in c.Win32_Process():
        lb1.insert(END,p.Name)
#t.insert(END,p)
def net_connection():
    print "**************************Current Conncetions and attirbutes**********"
    lbl2=Label(root,text="NET_Connection",font="Times 15 bold",fg="black").place(x=420,y=110)
    lb2.place(x=420,y=140,width=180,height=300)
    for p in psutil.net_connections(kind='inet'):
        lb2.insert(END,p) 
def pids():
    print "***************PID*********************"
    lbl3=Label(root,text="PIDs",font="Times 15 bold",fg="black").place(x=610,y=110)
    lb3.place(x=610,y=140,width=180,height=300)
    for p in psutil.pids():
        lb3.insert(END,p)
        
def running_services():       
    print "**********windows Service Running******"
    c=wmi.WMI()
    for s in c.Win32_Service():
        if s.State=='Running':
            print s.Caption
def stopped_services():
    print "*********windows stopped services*******"
    c=wmi.WMI()
    for s in c.Win32_Service():
        if s.State=='Stopped':
            print s.Caption

def task_list():
    print "****************Task list**************"
    for t in os.popen('tasklist').read():
        print t
#thread process

def nw_process_thread():
    pythoncom.CoInitialize()
    c=wmi.WMI()
    pwatch=c.Win32_Process.watch_for("creation")
    while True:
        newp=pwatch()
        lb4.insert(END,newp.Caption)
    
def nw_process():
    lbl4=Label(root,text="New Born Process",font="Times 15 bold",fg="black").place(x=800,y=110)
    lb4.place(x=800,y=140,width=180,height=300)
    threads=[]
    t=threading.Thread(target=nw_process_thread)
    threads.append(t)
    t.start()
#net connection function and thread***************************
def nw_connection_thread():
    print "heloo"
    # Get the list of interfaces we can listen on
    ifs = findalldevs()

    # No interfaces found
    if len(ifs) == 0:
        raise RuntimeError, "Error: no available network interfaces, or you don't have enough permissions on this system."

    # A single interface was found
    if len(ifs) == 1:
        interface = ifs[0]

    # Multiple interfaces found
    else:
        print "Available network interfaces:"
        for i in xrange(len(ifs)):
            print '\t%i - %s' % (i + 1, ifs[i])
        print
        while 1:
            #choice = raw_input("Choose an interface [0 to quit]: ")
            try:
                i = int(choice+1)
                if i == 0:
                    interface = None
                    break
                interface = ifs[i-1]
                break
            except Exception:
                pass

    # Return the selected interface
    #return interface
    sniff(interface)

def sniff(interface):
    print "Listening on: %s" % interface

    # Open a live capture
    reader = open_live(interface, 1500, 0, 100)

    # Set a filter to be notified only for TCP packets
    reader.setfilter('ip proto \\tcp')

    # Run the packet capture loop
    #threads=[]
    #t1=threading.Thread(target=reader.loop(0, callback))
    #threads.append(t1)
    #t1.start()
    reader.loop(0, callback)

def callback(hdr, data):

    # Parse the Ethernet packet
   # print "i am in callback"
    pythoncom.CoInitialize()
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(data)

    # Parse the IP packet inside the Ethernet packet
    iphdr = ether.child()

    # Parse the TCP packet inside the IP packet
    tcphdr = iphdr.child()

    # Only process SYN packets
    if tcphdr.get_SYN() and not tcphdr.get_ACK():

        # Get the source and destination IP addresses
        src_ip = iphdr.get_ip_src()
        dst_ip = iphdr.get_ip_dst()

        # Print the results
        #print "Connection attempt %s -> %s" % (src_ip, dst_ip)
        #lb5.insert(END,"sdfsfdsfsf")
        lb5.insert(END," %s -> %s" % (src_ip, dst_ip))
    
def nw_connection():
    lbl5=Label(root,text="New Net Connection",font="Times 15 bold",fg="black").place(x=990,y=110)
    lb5.place(x=990,y=140,width=180,height=300)
    threads=[]
    t=threading.Thread(target=nw_connection_thread)
    threads.append(t)
    t.start()
#network devices
def net_devices():
    lbl6=Label(root,text="Select Network Device",font="Times 15 bold",fg="black").place(x=1180,y=110)
    lb6.place(x=1180,y=140,width=180,height=300)
    devices=pcapy.findalldevs()
    for d in devices:
        lb6.insert(END,d)
net_devices()
def onselect(evt):
    w=evt.widget
    choice=int(w.curselection()[0])
    value=w.get(choice)
    nw_connection()
    print "sdfsfsf"
lb6.bind('<<ListboxSelect>>',onselect)
#********************************************************
#progress bar
progressbar = ttk.Progressbar(orient=HORIZONTAL, length=200, mode='indeterminate')
progressbar.pack(side="bottom",fill=X)
progressbar.start(100)
#scrollbar
sv=Scrollbar(root)
sv.pack(side=RIGHT,fill=Y)
sh=Scrollbar(root,orient=HORIZONTAL)
sh.pack(side=BOTTOM,fill=X)
#logo image
logo=PhotoImage(file="C:/Users/Cyber Dom/Desktop/projects ppts/EagleEyeFull_Web.gif")
lg=Label(root,image=logo).place(x=2,y=2)
#label
l=Label(root,
        text="Project:Eagle Eye on Computer",
        width=25,font="Verdana 25 bold",
        fg="black").place(x=300,y=30)
#list box1

#for p in psutil.pids():
 #   lb1.insert(END,p)
#button 1
b1=Button(root,width=18,relief=RAISED,
          text="Process",font="Times 10 bold",
          fg="black",
          command=lambda:process_detail()).place(x=20,y=120,width=150,height=40)
#button 2
b2=Button(root,width=18,text="Net Connections",
          font="Times 10 bold",fg="black",
          command=lambda:net_connection()).place(x=20,y=170,width=150,height=40)
#button 3
b3=Button(root,width=18,text="PIDs",
          font="Times 10 bold",fg="black",
          command=lambda:pids()).place(x=20,y=220,width=150,height=40)
#button 4
b4=Button(root,width=18,text="Running Services",
          font="Times 10 bold",fg="black",
          command=lambda:running_services()).place(x=20,y=270,width=150,height=40)
#button 5
b5=Button(root,width=18,text="Stopped Services",
          font="Times 10 bold",fg="black",
          command=lambda:stopped_services()).place(x=20,y=320,width=150,height=40)
#button 6
b6=Button(root,width=18,text="Task list",
          font="Times 10 bold",fg="black",
          command=lambda:task_list()).place(x=20,y=370,width=150,height=40)
#button 7
b7=Button(root,width=18,text="New Born Process",
          font="Times 10 bold",fg="black",
          command=lambda:nw_process()).place(x=20,y=420,width=150,height=40)
#button 8
b8=Button(root,width=18,text="New Net Connection",
          font="Times 10 bold",fg="black",
          command=lambda:nw_connection()).place(x=20,y=470,width=150,height=40)
mainloop()

        
    



    


