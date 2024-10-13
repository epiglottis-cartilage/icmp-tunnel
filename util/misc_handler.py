import socket


def get_local_ip() -> str:
    '''create a socket and get ip, then shutdown the socket

    return: ip
    error handling: return localhost if error occur
    side effect: create a socket and close it, takes little resources

    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to reach the address actually
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

    
