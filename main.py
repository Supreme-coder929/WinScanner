from tkinter import *
import scapy.all as scapy
import psutil
import re
import sys
import csv


try:
    net_info = psutil.net_if_addrs()
    temp_re = re.compile("enp0s[0-9]|wlan[0-9]|Wi-Fi")
    find_interface = re.search(temp_re, str(net_info))
    interface = net_info[find_interface.group()][1]
except AttributeError:
    sys.exit("Invalid Interface.")


private_ip = interface.address
subnet_mask = interface.netmask


gateway_ip = private_ip.replace(private_ip.split('.')[3], "1")
starting_lan_ip = private_ip.replace(private_ip.split('.')[3], "0")
subnet_prefix = sum(bin(int(x)).count("1") for x in subnet_mask.split("."))


root = Tk()
root.geometry("700x600")
root.title("WinScanner")
root.config(bg="#808080")
root.resizable(width=0,height=0)


def scan_network():
    global network_hosts

    network_results.config(state="normal")
    network_results.delete("1.0", END)
    network_hosts = dict()
    network_results.insert(INSERT, "Sending LAYER 2 packets....\n")
    broadcast_block = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_block = scapy.ARP(pdst=f"{starting_lan_ip}/{subnet_prefix}")

    data = scapy.srp(broadcast_block/arp_block, timeout=5, verbose=0)[0]
    for host in data:
        network_hosts[str(host[1].psrc)] = str(host[1].hwsrc)

    for live_host in network_hosts.items():
        network_results.insert(INSERT, f"\nIP: {live_host[0]} MAC: {live_host[1]}")

    network_results.insert(INSERT, f"\nTotal Live Hosts: {len(network_hosts)}")


def export_csv():
    if len(network_results.get("1.0", "end-1c")) > 0:
        with open("hosts.csv", "w", newline="") as f:
            out = csv.writer(f)
            for live_host in network_hosts.items():
                out.writerow([str(live_host[0]), str(live_host[1])])
            network_results.insert(INSERT, "\n File hosts.csv succesfully created. \n")
    else:
        pass


network_results = Text(
    root,
    fg="#13e200",
    bg="#010000",
    state="disabled",
    padx=40,
    pady=40
    )
network_results.pack(side="top")

scan_network = Button(
    root,
    command=scan_network,
    text="Scan Network",
    font=('Arial',20,'bold'),
    borderwidth=1,
    padx=75,
    pady=30
    )
scan_network.place(x=0, y=500)


export_to_csv = Button(
    root,
    command=export_csv,
    text="Export to CSV",
    font=('Arial',20,'bold'),
    borderwidth=1,
    padx=75,
    pady=30

)
export_to_csv.place(x=350, y=500)

root.mainloop()