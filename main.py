from scapy.all import *
from sys import argv
import Gnuplot

if __name__ == "__main__":
    filename = argv[1]
    pcap = rdpcap(filename)
    arp_wh = pcap.filter(lambda x : x.haslayer(ARP) and x[ARP].op == 1 )

    d = {}
    for i in arp_wh:
        d[i.psrc] = d.get(i.psrc, 0) + 1


    str(d).replace(":", "").replace("'", "").replace(",", "\n").replace("{", "").replace("}", "")
    print str(d).replace(":", "").replace("'", "").replace(",", "\n").replace("{", "").replace("}", "")

    g = Gnuplot.Gnuplot(debug=1)
    g.title('A simple example') # (optional)

    g('set data style linespoints') # give gnuplot an arbitrary command
    g.plot( list(d.items() ))
