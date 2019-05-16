import SimpleHTTPServer
import SocketServer
import sys, getopt
import socket

def main(argv):
    PORT = ''
    try:
        opts, args = getopt.getopt(argv,"p:",["portnumber="]);
    except getopt.GetoptError:
        print 'server.py -p <portnumber>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-p':
            PORT= int(arg)
    print "serving at port", PORT
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((socket.gethostname(), PORT))
    serversocket.listen(0)
    print "\nOK"
if __name__ == "__main__":
    main(sys.argv[1:])
    exit(0)
