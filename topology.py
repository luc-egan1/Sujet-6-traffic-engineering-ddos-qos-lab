#!/usr/bin/env python3
"""Topologie Mininet isolée : deux émetteurs, un serveur, lien serveur à 10 Mbit/s."""

from mininet.link import TCLink
from mininet.topo import Topo


class DDoSQoSTopo(Topo):
    """h1 (voix) et h2 (charge) partagent le switch s1 et le lien goulot vers h3."""

    def build(self):
        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h3 = self.addHost("h3", ip="10.0.0.3/24")
        s1 = self.addSwitch("s1")
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1, cls=TCLink, bw=10, max_queue_size=100)


topos = {"ddosqos": lambda: DDoSQoSTopo()}

