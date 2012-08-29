from scapy.all import *
from sys import argv
import matplotlib.pyplot as plt

def plot_hist(di, name, xtag, ytag, figid ):
    print "figid", figid

    fig= plt.figure(figid, figsize=(20,15), dpi=100)

    ax= fig.add_subplot(1,1,1)

    labels = []
    y_list = []
    x_list = range(len(di))

    for k, v in di.items():
        y_list.append(v)
        labels.append(k)

    ax.bar(x_list, y_list, width = 0.3)
    ax.set_xlabel(xtag)
    ax.set_ylabel(ytag)
    ax.set_title(name)

    plt.xticks(x_list, labels, rotation = 90)
    plt.savefig("%s.png" % name.replace(" ", ""), dpi = 100)
    #plt.show()


if __name__ == "__main__":
    filename = argv[1]
    pcap = rdpcap(filename)
    arp_wh = pcap.filter(lambda x : x.haslayer(ARP) and x[ARP].op == 1 )

    d = {}
    for i in arp_wh:
        d[i.psrc] = d.get(i.psrc, 0) + 1

    print d
    plot_hist(d, "IPs que mas piden", "IPs", "# Who-has", 0)

    d = {}
    for i in arp_wh:
        d[i.pdst] = d.get(i.pdst, 0) + 1
    plot_hist(d, "IPs mas pedidas", "IPs", "# Who-has", 1)



    arp_h = pcap.filter(lambda x : x.haslayer(ARP) and x[ARP].op == 2 )

    d = {}
    for i in arp_h:
        d[i.psrc] = d.get(i.psrc, 0) + 1

