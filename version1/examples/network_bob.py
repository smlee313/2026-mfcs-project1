import socket
import threading
import argparse
import logging

def handler(conn):
    while True:
        msg = conn.recv(1024)

        if not msg:
            print("Alice disconnected.")
            break

        received = msg.decode("ascii")
        print("Alice >", received)

        if received.lower() == "bye":
            break

        message = input("Bob > ")

        conn.send(message.encode("ascii"))
        logging.info("[*] Sent: {}".format(message))

        if message.lower() == "bye":
            break

    conn.close()


def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    bob.bind((addr, port))
    bob.listen(10)

    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info(
            "[*] Bob accepts the connection from {}:{}".format(
                info[0], info[1]
            )
        )

        conn_handle = threading.Thread(
            target=handler,
            args=(conn,)
        )

        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-a", "--addr",
        metavar="<bob's IP address>",
        type=str,
        default="0.0.0.0"
    )

    parser.add_argument(
        "-p", "--port",
        metavar="<bob's open port>",
        type=int,
        required=True
    )

    parser.add_argument(
        "-l", "--log",
        metavar="<log level>",
        type=str,
        default="INFO"
    )

    return parser.parse_args()


def main():
    args = command_line_args()

    logging.basicConfig(level=args.log)

    run(args.addr, args.port)


if __name__ == "__main__":
    main()