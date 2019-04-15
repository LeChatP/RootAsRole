import SimpleHTTPServer
import SocketServer
import sys, getopt
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
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("",PORT),Handler)
    print "serving at port", PORT
    httpd.serve_forever()
    httpd.server_close()
    print "OK"
if __name__ == "__main__":
    main(sys.argv[1:])
