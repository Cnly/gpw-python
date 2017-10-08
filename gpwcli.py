import sys
import getpass
import gpwcore

if __name__ == "__main__":
    password = getpass.getpass("Password:")

    if len(sys.argv) != 2:
        key = input('Key:')
    else:
        key = sys.argv[1]

    print(gpwcore.gpw(password, key))