import socket

def start_server(host='0.0.0.0', port=4445):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[*] Listening on {host}:{port}")

    client_socket, addr = server_socket.accept()
    print(f"[*] Accepted connection from {addr}")

    while True:
        command = input("Enter command: ")
        client_socket.send(command.encode())

        if command.lower() == 'exit':
            print("Exiting...")
            break

        response = client_socket.recv(4096).decode()
        print(f"[*] Response received:\n{response}")

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
