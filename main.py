import socket
import sys
from datetime import datetime

domain = input("Enter domain to scan: ")
domain = domain.replace("http://", "")
domain = domain.replace("https://", "")


def scan():
    try:
        with open('ports.csv', 'r') as csv_data:
            print("-" * 50)
            print("Easy Port Scanner - Suncoast Information Security")
            print("Started CSV scan at", str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            print("-" * 50)

            print("Port" + "\t" + "Status" + "\t" + "Description")
            print("Tested the following ports from CSV:")

            # Skipping the first title row, and opening blank variables for us to use.
            lines = csv_data.readlines()[1:]
            c_port = []
            c_desc = []

            # Defining how our CSV is formatted so we can read it.
            for line in lines:
                data = line.split(',')
                c_port.append(data[0])
                c_desc.append(data[1])

            # Now we loop for recursive discovery from CSV, and then running port check.
            for x in range(len(c_port)):
                fn_port = int(c_port[x])
                fn_desc = str(c_desc[x])

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((domain, fn_port))
                sock.settimeout(10)
                sock.close()

                if result == 0:
                    print(fn_port, " - Open - ", fn_desc)
                    sock.close()

                elif result != 0:
                    print(fn_port, " - Closed - ", fn_desc)
                    sock.close()

    # Exception handles
    except KeyboardInterrupt:
        print("\n Keyboard abort pressed, process stopped.")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("\n Server not responding.")
        sys.exit()


scan()
