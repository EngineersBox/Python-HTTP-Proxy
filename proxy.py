import socket, threading, re, time, logging, signal, sys
from typing import Dict, Tuple
from bs4 import BeautifulSoup

# ==== CONSTANTS ====

BUFFER_SIZE = 4096

SERVER_HOST = "comp3310.ddns.net"
SERVER_PORT = 80

PROXY_HOST = "localhost" #I'm the host
PROXY_PORT = 8080

CONNECTION_MAX_RETRY = 10

TCP_PACKET_SECTION_ENDING = bytes("\r\n\r\n", encoding="utf8")
HTTP_CONTENT_LENGTH_HEADER_KEY = re.compile("(C|c)ontent-(L|l)ength:\s([0-9]+)") #finds "C/content L/length" space and number, which is the length of the body 
HTTP_CONTENT_TYPE_HEADER_KEY = re.compile("(C|c)ontent-(T|t)ype:\s([\w/]+)")  #finds "C/content T/type" space and type, which is the length of the body 

HTML_HREF_ATTRIBUTE = "href" # Any HTML element with an href attribute. E.g. <a href="...">
HTML_SRC_ATTRIBUTE = "src" # Any HTML element with a src attribute. E.g. <img src="...">

TEXT_TO_REPLACE = {
    re.compile("(T|t)he"): "eht"
}

# ==== LOGGING ====

LOG_DATE_FORMAT = "%d/%m/%Y %H:%M:%S"
# An example log entry with this format is: [17/04/2022 23:22:53] [Sockets Proxy] [Thread-1] [DEBUG] :: Some test message (proxy.py:32)
LOG_FORMAT = "[{0}%(asctime)s\x1b[0m] [%(name)s] [{0}%(threadName)s\x1b[0m] [{1}%(levelname)s\x1b[0m] :: {2}%(message)s (%(filename)s:%(lineno)d)\x1b[0m"
LOG_LEVEL = logging.DEBUG
LOGGER: logging.Logger = None

class CustomFormatter(logging.Formatter):

    # ANSI standard colour codes
    ANSI_BRIGHT_BLUE = "\x1b[36;1m"
    ANSI_BLUE = "\x1b[36m"
    ANSI_GREY = "\x1b[38m"
    ANSI_YELLOW = "\x1b[33m"
    ANSI_PURPLE = "\x1b[35m"
    ANSI_GREEN = "\x1b[32m"
    ANSI_RED = "\x1b[31m"
    ANSI_BRIGHT_RED = "\x1b[31;1m"
    ANSI_RESET = "\x1b[0m"

    # Individual logging level formats. The format arguments are:
    # - 0: Datetime and thread name colour
    # - 1: Log level name colour
    # - 2: Message colour
    FORMATS = {
        logging.DEBUG: LOG_FORMAT.format(ANSI_PURPLE, ANSI_BLUE, ANSI_BLUE),
        logging.INFO: LOG_FORMAT.format(ANSI_PURPLE, ANSI_GREEN, ANSI_GREY),
        logging.WARNING: LOG_FORMAT.format(ANSI_PURPLE, ANSI_YELLOW, ANSI_YELLOW),
        logging.ERROR: LOG_FORMAT.format(ANSI_PURPLE, ANSI_RED, ANSI_RED),
        logging.CRITICAL: LOG_FORMAT.format(ANSI_PURPLE, ANSI_BRIGHT_RED, ANSI_BRIGHT_RED),
    }

    def format(self, record) -> str:
        log_fmt = self.FORMATS.get(record.levelno) # Retrieve the logging level from the recording being logged
        formatter = logging.Formatter(log_fmt, LOG_DATE_FORMAT) # Create a formatter using our logging format
        return formatter.format(record)

def init_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name) # Create a new logger with a name
    log.setLevel(LOG_LEVEL) # Set the level of messages that will be included. Anything at this level or above are included

    ch = logging.StreamHandler() # Get the handler to configure the logger further
    ch.setFormatter(CustomFormatter()) # Set our custom formatter in the logger

    log.addHandler(ch) # Configure the logger to use the customer handler
    return log

# ==== PACKET PROCESSING ====

def parse_HTML(data: bytes) -> BeautifulSoup:
    return BeautifulSoup(data, "html.parser") # Parse the data assuming HTML4 formatting

def replace_links(soup: BeautifulSoup) -> BeautifulSoup:
    tags_with_href_attribute = soup.select(f"[{HTML_HREF_ATTRIBUTE}]") # Find any tag that has the href attribute. E.g. <a href="...">
    LOGGER.debug(f"Found href tags: {len(tags_with_href_attribute)}")
    for href_tag in tags_with_href_attribute:
        href_tag.attrs[HTML_HREF_ATTRIBUTE] = href_tag.attrs[HTML_HREF_ATTRIBUTE].replace(SERVER_HOST, PROXY_HOST) # Replace any usage of the server host with the proxy so that traffic goes through proxy only
    
    tags_with_src_attribute = soup.select(f"[{HTML_SRC_ATTRIBUTE}]") # Find any tag that has the src attribute. E.g. <img src="...">
    LOGGER.debug(f"Found src tags: {len(tags_with_src_attribute)}")
    for src_tag in tags_with_src_attribute:
        src_tag.attrs[HTML_SRC_ATTRIBUTE] = src_tag.attrs[HTML_SRC_ATTRIBUTE].replace(SERVER_HOST, PROXY_HOST) # Replace any usage of the server host with the proxy so that traffic goes through proxy only
    return soup

def replace_in_text(soup: BeautifulSoup, replacements: Dict[re.Pattern,str]) -> BeautifulSoup:
    for tag in soup.findAll(recursive=True, text=True): # Recursively iterate over all HTML text elements
        for key, value in replacements.items(): # Iterate over all the key,value pairs of regex search text and the replacements
            if key.search(tag.string) != None: # If the regex key matches the element text, we replace the matching text section
                tag.replaceWith(key.sub(value, tag.string))
    return soup


def handle_html_data(content_length: int, header: bytes, body: bytes, ) -> Tuple[bytes, bytes]:
    try:
        soup = parse_HTML(body)
        # Replace the links with href and src attributes to ensure traffic goes through proxy
        soup = replace_links(soup)
        # Replace text elements based on our dictionary of mappings
        soup = replace_in_text(soup, TEXT_TO_REPLACE)
        # Re-encode the changed HTML into bytes
        new_body = soup.encode(encoding="utf-8", formatter="html")
        new_header = header.replace(
            bytes(f"Content-Length: {content_length}", encoding="utf-8"),
            bytes(f"Content-Length: {len(new_body)}", encoding="utf-8")
        )  # Update the Content-Length header with the new length
        return len(new_body), new_header, new_body
    except Exception as e:
        LOGGER.warn(f"Packet was not HTML, forwarding to client: {e}") # Something we wrong when trying to change the HTML so we will just send the original data
        return content_length, header, body

# ==== TCP READ HANDLING ====

def read_until_tcp_section_ending(sock: socket.socket) -> Tuple[str, str]: # detects \r\n\r\n to find the body
    buffer = sock.recv(BUFFER_SIZE) # reads 4096bytes at once
    buffering = True
    while buffering:
        if TCP_PACKET_SECTION_ENDING in buffer:  # get to the end of the header, which is \r\n\r\n"
            (line, buffer) = buffer.split(TCP_PACKET_SECTION_ENDING, 1)
            return line + TCP_PACKET_SECTION_ENDING, buffer  # seperating header + r\n\r\n and the body
        else:
            more = sock.recv(BUFFER_SIZE) # if we haven't reached the end of the header, we'll keep on reading 
            if not more:
                buffering = False #h eaders finshed or not complete
            else:
                buffer += more # adds new read bytes to the buffer to process
    return buffer, ""  # return whatever the termination of the connection

def find_content_length(header: str) -> int: #find the length of the body, return it in integer
    if len(header) <= len("content-length:"): #if the lenght of the header is less than the length of the character in "content-length" return 0
        return 0
    match = HTTP_CONTENT_LENGTH_HEADER_KEY.search(str(header))
    if match == None:
        return 0
    return int(match.group(3)) #if the header is successfully found, return the value of the header

def find_content_type(header: str) -> str: #find the type of the body
    if len(header) <= len("content-type:"): #if the lenght of the header is less than the length of the character in "content-type" return empty string
        return ""
    match = HTTP_CONTENT_TYPE_HEADER_KEY.search(str(header))
    if match == None:
        return ""
    return match.group(3) #if the header is successfully found, return the value of the header

def read_all_chunks(total_length: int, sock: socket.socket) -> bytes:
    buffer = bytes()
    while len(buffer) < total_length:
        buffer += sock.recv(BUFFER_SIZE)
    return buffer

def read_tcp_packet(sock: socket.socket) -> Tuple[int, bytes, bytes]:
    # Find the headers and return any excess we read (part of the body) as well
    header, excess_buffer = read_until_tcp_section_ending(sock)
    if (len(header) < 1):
        return 0, b"", b""

    str_header = header.decode("utf-8")
    LOGGER.info(f"Server Response Header: {str_header}")
    content_length = find_content_length(header)  # Get the value of the Content-Length header in order to tell how many bytes the body is
    LOGGER.debug(f"Content length {content_length}")

    body = excess_buffer  # Any excess that was read will be part of the body, so this is our starting point
    to_read = content_length - len(excess_buffer)
    body += read_all_chunks(to_read, sock)  # Read the rest of the body as indicated by the content-length header minus how much we have already read
    return content_length, header, body

# ==== CONNECTION ====

def proxy_to_server_socket() -> socket.socket: #creating a socket to connect the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #using ipv4 and tcp connection
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.connect((SERVER_HOST, SERVER_PORT)) 
    return sock

def client_to_proxy_socket() -> socket.socket: #creat a socket between the client and the proxy
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((PROXY_HOST, PROXY_PORT))
    sock.listen() #can have 5 opened connections at the same time
    return sock

SERVER_HANDLER_RUNNING = True
CLIENT_HANDLER_RUNNING = True

def handle_server_response(server_conn: socket.socket, client_conn: socket.socket) -> None: #This thread forwards the server response to the client
    global SERVER_HANDLER_RUNNING
    LOGGER.info("Connected to server")
    while SERVER_HANDLER_RUNNING:
        try:
            content_length, header, body = read_tcp_packet(server_conn) # receive response from the server
            if content_length < 1: # If there is no data, wait for the next packet's headers
                continue
            content_type = find_content_type(header)
            LOGGER.debug(f"Content type: {content_type}")

            if "html" in content_type: # If we have HTML, we can try to parse it and change elements of it
                content_length, header, body = handle_html_data(content_length, header, body)
                LOGGER.debug(f"New HTML Content length: {content_length}")
            
            if len(body) > 0:
                # proxy sending the server response to the client
                client_conn.sendall(header + body)
        except socket.error as e:
            LOGGER.warn(f"Server connection was interrupted, retrying for {CONNECTION_MAX_RETRY} attempts: {e}")
            retry_count = 0
            while retry_count < CONNECTION_MAX_RETRY:
                try:
                    LOGGER.info(f"Server connection retry {retry_count + 1}")
                    server_conn, _ = server_conn.connect((SERVER_HOST, SERVER_PORT))
                    LOGGER.info(f"Server connection restablished")
                    break
                except socket.error:
                    time.sleep(1)
                    retry_count += 1
            if retry_count >= CONNECTION_MAX_RETRY:
                LOGGER.error(f"Failed to restablish connection to server.")
                SERVER_HANDLER_RUNNING = False
    server_conn.close()
    client_conn.close()

def handle_client_request(server_conn: socket.socket, client_conn: socket.socket, client_addr) -> None: #This thread handles the incoming client requests and then forward it to the server
    global CLIENT_HANDLER_RUNNING
    LOGGER.info(f"Connected to client {client_addr}")
    while CLIENT_HANDLER_RUNNING:
        try:
            data = client_conn.recv(4096)  # proxy receiving the client request
            if len(data) > 0:
                str_data = data.decode("utf-8")
                LOGGER.info(f"Client Request: {str_data}")
                # sending the client request to the server (from proxy)
                server_conn.sendall(data)
        except socket.error as e:
            LOGGER.error(f"Client connection was interrupted: {e}")
            CLIENT_HANDLER_RUNNING = False
    server_conn.close()
    client_conn.close()

# ==== MAIN ====

def main():
    global LOGGER
    LOGGER = init_logger("Sockets Proxy")

    client_conn, client_addr = client_to_proxy_socket().accept() #if client to proxy connection is made, return client socket and the address

    original_sigint = signal.getsignal(signal.SIGINT)
    def irq_handler(signum, _frame):
        signal.signal(signal.SIGINT, original_sigint) # Allow interrupt to be re-entrant incase CTRL-C is pressed during this method
        LOGGER.debug(f"Signal handler called with signal: {signum}")
        global SERVER_HANDLER_RUNNING
        global CLIENT_HANDLER_RUNNING

        SERVER_HANDLER_RUNNING = False # Stop server handler loop
        CLIENT_HANDLER_RUNNING = False # Stop client handler loop

        server_conn.close() # Close server connection
        client_conn.close() # Close client connection
        signal.signal(signal.SIGINT, irq_handler) # Restore current handler
        sys.exit(0)

    signal.signal(signal.SIGINT, irq_handler) # Register an interrupt handler for SIGINT so we can close connections properly

    server_conn = proxy_to_server_socket()
    server_thread = threading.Thread(target=handle_server_response, args=(server_conn,client_conn))
    server_thread.setDaemon(True) #run in background so that the subsequenct threads will terminate once the main thread ends
    server_thread.start()

    handle_client_request(server_conn, client_conn, client_addr)

if __name__ == '__main__':
    main()
