import socket

while True:
  s = socket.socket()
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # allows immediate port reuse
  hostname = "localhost"
  port = 8080

  try: 
    s.bind((hostname, port))

    s.listen()

    conn, addr = s.accept()
    print(f"Got connection from {addr}")

    while True:
      try:
        data = conn.recv(1024)
        print(data.decode())

        if not data:  # Handle connection closed
          print("Client disconnected")
          break

      except:
        break

  except KeyboardInterrupt:
      print("\nDisconnected")
      break

  finally:
      s.close()