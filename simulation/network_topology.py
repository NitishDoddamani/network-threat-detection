"""
Mininet network topology for attack simulation.
Creates a realistic network with attacker, victim, and router nodes.

Topology:
  attacker (h1) ─┐
  victim   (h2) ─┤── switch (s1) ── router (h3)
  monitor  (h4) ─┘
"""
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
import time
import threading

def create_topology():
    setLogLevel('warning')

    net = Mininet(
        controller=Controller,
        switch=OVSSwitch,
        link=TCLink
    )

    print("🌐 Creating network topology...")

    # Add controller
    c0 = net.addController('c0')

    # Add switch
    s1 = net.addSwitch('s1')

    # Add hosts
    attacker = net.addHost('attacker', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    victim   = net.addHost('victim',   ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    monitor  = net.addHost('monitor',  ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    server   = net.addHost('server',   ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    # Add links
    net.addLink(attacker, s1)
    net.addLink(victim,   s1)
    net.addLink(monitor,  s1)
    net.addLink(server,   s1)

    net.start()
    print("✅ Network topology started!")
    print("   attacker → 10.0.0.1")
    print("   victim   → 10.0.0.2")
    print("   monitor  → 10.0.0.3")
    print("   server   → 10.0.0.4")

    return net, attacker, victim, monitor, server
