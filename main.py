from scapy.all import *
from sys import argv
import matplotlib.pyplot as plt

def plot_hist(di, name, xtag, ytag):

    fig= plt.figure(1, figsize=(20,15), dpi=100)

    ax= fig.add_subplot(1,1,1)

    labels = []
    y_list = []
    x_list = range(len(di))

    for k, v in di.items():
        y_list.append(v)
        labels.append(k)

    ax.bar(x_list, y_list, width = 0.3)
    ax.set_xlabel('IPs')
    ax.set_ylabel('#Who-has')
    ax.set_title('IPs mas pedidas')

    plt.xticks(x_list, labels, rotation = 90)
    plt.savefig("%s.png" % name, dpi = 100)
    plt.show()


if __name__ == "__main__":
    filename = argv[1]
    pcap = rdpcap(filename)
    arp_wh = pcap.filter(lambda x : x.haslayer(ARP) and x[ARP].op == 1 )

    d = {}
    for i in arp_wh:
        d[i.psrc] = d.get(i.psrc, 0) + 1

    
    print d
    plot_hist(d)


    str(d).replace(":", "").replace("'", "").replace(",", "\n").replace("{", "").replace("}", "")
    print str(d).replace(":", "").replace("'", "").replace(",", "\n").replace("{", "").replace("}", "")

#    g = Gnuplot.Gnuplot(debug=1)
#    g.title('A simple example') # (optional)
#
#    g('set data style linespoints') # give gnuplot an arbitrary command
#    g.plot( list(d.items() ))
#
