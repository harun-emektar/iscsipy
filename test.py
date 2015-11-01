#!/usr/bin/python3

import initiator

if __name__ == "__main__":
    # Create a initiator
    init = initiator.Initiator("iqn.2006-11.1")
    init.Connect("localhost:3260")
    init.Login()
    targets = init.Discovery()
    for t in targets:
        print(t.name + "=>", end="")
        for a in t.addr_list:
            print(a.addr + "," + str(a.tpgt) + ";", end = "")
        print()
    init.Logout()