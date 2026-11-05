import socket
import argparse
import logging

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    while True:
        message = input("Alice > ")

        conn.send(message.encode("ascii"))
        logging.info("[*] Sent: {}".format(message))

        if message.lower() == "bye":
            break

        msg = conn.recv(1024)

        if not msg:
            print("Bob disconnected.")
            break

        print("Bob >", msg.decode("ascii"))

    conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a", "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True
    )
    parser.add_argument(
        "-p", "--port",
        metavar="<bob's port>",
        help="Bob's port",
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