from tkinter import *
from tkinter import Tk, Frame, Scrollbar, Label, END, Entry, Text, VERTICAL, Button, messagebox #Tkinter Python Module for GUI  
import base64
import socket #Sockets for network connection
import threading # for multiple proccess
import frames_run as frr

class Encoder:
    client_socket = None
    last_received_message = None

    #Class Variables
    Text = StringVar()
    private_key = StringVar()
    mode = StringVar()
    Result = StringVar()

    def __init__(self, master):
        self.root = master
        self.chat_transcript_area = None
        self.name_widget = None
        self.enter_text_widget = None
        self.join_button = None
        self.initialize_socket()
        self.initialize_gui()
        self.listen_for_incoming_messages_in_a_thread()

    #Initializing socket
    def initialize_socket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # initialazing socket with TCP and IPv4
        remote_ip = '127.0.0.1'  # IP address
        remote_port = 10319  # TCP port
        self.client_socket.connect((remote_ip, remote_port))  # connect to the remote server


    # GUI initializer
    def initialize_gui(self): 
        self.root.title("Python - Message Encode and Decode")
        self.root.resizable(0, 0)
        self.display_name_section()
        self.display_chat_entry_box()
        self.display_chat_box()

    #To receive messages
    def listen_for_incoming_messages_in_a_thread(self):
        thread = threading.Thread(target=self.receive_message_from_server,
                                  args=(self.client_socket,))  # Create a thread for the send and receive in same time
        thread.start()

    # function to recieve msg
    def receive_message_from_server(self, so):
        while True:
            buffer = so.recv(256)
            if not buffer:
                break
            message = buffer.decode('utf-8')

            if "joined" in message:
                user = message.split(":")[1]
                message = user + " has joined"
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)
            else:
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)

        so.close()

    def display_name_section(self):
        frame = Frame()
        Label(frame, text='Enter Your Name Here! ', font=("arial", 13, "bold")).pack(side='left', pady=20)
        self.name_widget = Entry(frame, width=60, font=("arial", 13))
        self.name_widget.pack(side='left', anchor='e', pady=15)
        self.join_button = Button(frame, text="Join", width=10, command=self.on_join).pack(side='right', padx=5, pady=15)
        frame.pack(side='top', anchor='nw')


    #Function to encode message
    def Encode(self, key,message):
        enc=[]

        for i in range(len(self.message)):
            key_c = self.key[i % len(key)]
            self.enc.append(chr((ord(message[i]) + ord(key_c)) % 256))
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()

    
    #Function to show private key button
    def priv_key_button(self):
        frame = Frame()
        Label(frame, font = 'arial 12 bold', text ='KEY').place(x=60, y = 90)
        self.key_entry = Entry(frame, font = 'arial 10', textvariable = self.private_key , bg ='ghost white').place(x=290, y = 90)
        

    #Function to decode message
    def Decode(self, key,message):
        dec=[]
        message = self.base64.urlsafe_b64decode(message).decode()

        for i in range(len(self.message)):
            key_c = self.key[i % len(key)]
            self.dec.append(chr((256 + ord(message[i])- ord(key_c)) % 256))
        return "".join(dec)

    #Function to input mode
    def Mode_set(self):
        frame = Frame()
        Label(frame, font = 'arial 12 bold', text ='MODE(e-encode, d-decode)').place(x=60, y = 120)
        self.get_mode = Entry(frame, font = 'arial 10', textvariable = mode , bg= 'ghost white').place(x=290, y = 120)

    #Function to process the mode
    def Mode(self):
        if(self.mode.get() == 'e'):
            Result.set(Encode(private_key.get(), Text.get()))
        elif(self.mode.get() == 'd'):
            Result.set(Decode(private_key.get(), Text.get()))
        else:
            Result.set('Invalid Mode')


    #Function to reset information
    def Reset(self):
        self.Text.set("")
        self.private_key.set("")
        self.mode.set("")
        self.Result.set("")

    #Reset button
    def Reset_button(self):
        frame = Frame()
        self.reset_butt = Button(frame, font='arial 10 bold', text='RESET', width=6, bg='LimeGreen', padx=2, command=self.Reset).place(x=80,y=190)
        frame.pack(side='left')

    #Function to get send message
    def Result(self):
        frame=Frame()
        self.result_generate = Button(frame, font = 'arial 10 bold', text = 'RESULT'  ,padx =2,bg ='LightGray' ,command = self.Mode).place(x=60, y = 150)
        senders_name = self.name_widget.get().strip() + ": "
        message = (senders_name + RESULT).encode('utf-8')
        self.chat_transcript_area.insert('end', message.decode('utf-8') + '\n')
        self.chat_transcript_area.yview(END)
        self.client_socket.send(message)
        self.enter_text_widget.delete(1.0, 'end')
        return 'break'
        frame.pack(side='center')
    

    def display_name_section(self):
        frame = Frame()
        Label(frame, text='Enter Your Name Here! ', font=("arial", 13, "bold")).pack(side='left', pady=20)
        self.name_widget = Entry(frame, width=60, font=("arial", 13))
        self.name_widget.pack(side='left', anchor='e', pady=15)
        self.join_button = Button(frame, text="Join", width=10, command=self.on_join).pack(side='right', padx=5, pady=15)
        frame.pack(side='top', anchor='nw')

    def display_chat_box(self):
        frame = Frame()
        Label(frame, text='Chat Box', font=("arial", 12, "bold")).pack(side='top', padx=270)
        self.chat_transcript_area = Text(frame, width=60, height=10, font=("arial", 12))
        scrollbar = Scrollbar(frame, command=self.chat_transcript_area.yview, orient=VERTICAL)
        self.chat_transcript_area.config(yscrollcommand=scrollbar.set)
        self.chat_transcript_area.bind('<KeyPress>', lambda e: 'break')
        self.chat_transcript_area.pack(side='left', padx=15, pady=10)
        scrollbar.pack(side='right', fill='y', padx=1)
        frame.pack(side='left')

    def display_chat_entry_box(self):
        frame = Frame()
        Label(frame, text='Enter Your Message Here!', font=("arial", 12, "bold")).pack(side='top', anchor='w', padx=120)
        self.Text = Text(frame, width=50, height=10, font=("arial", 12))
        self.Text.pack(side='left', pady=10, padx=10)
        self.Text.bind('<Return>', self.on_enter_key_pressed)
        frame.pack(side='left')


    def on_join(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror( "Enter your name", "Enter your name to send a message")
            return
        self.name_widget.config(state='disabled')
        self.client_socket.send(("joined:" + self.name_widget.get()).encode('utf-8'))

    def on_enter_key_pressed(self, event):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror("Enter your name", "Enter your name to send a message")
            return
        self.send_chat()
        self.clear_text()

    def clear_text(self):
        self.enter_text_widget.delete(1.0, 'end')

    #def send_chat(self):
     #   senders_name = self.name_widget.get().strip() + ": "
     #   data = self.enter_text_widget.get(1.0, 'end').strip()
     #   message = (senders_name + data).encode('utf-8')
     #   self.chat_transcript_area.insert('end', message.decode('utf-8') + '\n')
     #   self.chat_transcript_area.yview(END)
     #   self.client_socket.send(message)
     #   self.enter_text_widget.delete(1.0, 'end')
     #   return 'break'

    #Function to go to home page
    def Go_home(self):
        frame = Frame()
        self.home_button = Button(frame, text ="Home", command = lambda : controller.frr.show_frame(StartPage))
        frame.pack(side='bottom')


#the main function
if __name__ == '__main__':
    root = Tk()
    gui = Encoder(root)
    root.protocol("WM_DELETE_WINDOW", Encoder.on_close_window)
    root.mainloop()
