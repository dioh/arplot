""" TODO LIST:
 * Arreglar el histograma
    * rayas en el histo
    * mover primer barra a derecha
    * el texto se tiene q notar mejor
 * El arrow graph

    """


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


def get_rep_graph(arplist):
    graph = {}

    sp = {}
    for i in arplist:
        #graph.append((i.psrc, i.pdst))
        graph[i.psrc] = i.pdst
        sp[i.psrc] = ()
        sp[i.pdst] = ()

    # Now I generate the space where it should be represented, ie: x, y coordinates for each node:

    x,  y = 0, 0

    ancho = alto = 20
    inc = 20 / 5 # 5 nodos por fila

    for k,v in sp.items():
        v = (x, y)
        x = x + inc
        if x == ancho:
            y = (y + inc)
            x =  (x + inc) % ancho
        sp[k] = v

    print sp
    return  graph.items()


def plot_graph(rel, file_name):
    import pydot # import pydot or you're not going to get anywhere my friend :D 

    # first you create a new graph, you do that with pydot.Dot()
    #graph = pydot.Dot(graph_type='digraph')

    graph = pydot.graph_from_edges(rel, directed = True)
    graph.write_png(file_name)

    #nodes = [pydot.Node(ip, style = "filled", fillcolor="#0000ff") for ip in ips ]
    #for n in nodes: 
    #    graph.add_node(n)
    #
    #for s, d in rel:
    #    graph.add_edge(pydot.Edge(node_d, node_a, color="blue"))



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


    arp_wh = pcap.filter(lambda x : x.haslayer(ARP) and x[ARP].op == 1 )
    relations = get_rep_graph(arp_wh)

    plot_graph(relations, "comunicaciones.png")
