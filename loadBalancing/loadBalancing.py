# !/usr/bin/python

# from mininet.net import Mininet
# from mininet.node import Controller, RemoteController, OVSController
# from mininet.node import CPULimitedHost, Host, Node
# from mininet.node import OVSKernelSwitch, UserSwitch
# from mininet.node import RemoteController
# from mininet.node import IVSSwitch
# from mininet.cli import CLI
# from mininet.log import setLogLevel, info
# from mininet.link import TCLink, Intf
# from subprocess import call

# def myNetwork():

#     net = Mininet(controller=RemoteController)

#     info( '*** Adding controller\n' )
#     c0 = net.addController('c0', ip='134.34.231.214')

#     info( '*** Add switches\n')
#     s5 = net.addSwitch('s5', protocols="OpenFLow13")
#     s2 = net.addSwitch('s2', protocols="OpenFLow13")
#     s4 = net.addSwitch('s4', protocols="OpenFLow13")
#     s1 = net.addSwitch('s1', protocols="OpenFLow13")
#     s3 = net.addSwitch('s3', protocols="OpenFLow13")

#     info( '*** Add hosts\n')
#     h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
#     h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)

#     info( '*** Add links\n')
#     net.addLink(h1, s1)
#     net.addLink(s1, s2)
#     net.addLink(s2, s5)
#     net.addLink(s5, h3)
#     net.addLink(s5, s4)
#     net.addLink(s4, s3)
#     net.addLink(s3, s1)

#     info( '*** Starting network\n')
#     net.build()
#     info( '*** Starting controllers\n')
#     for controller in net.controllers:
#         controller.start()

#     info( '*** Starting switches\n')
#     net.get('s5').start([c0])
#     net.get('s2').start([c0])
#     net.get('s4').start([c0])
#     net.get('s1').start([c0])
#     net.get('s3').start([c0])

#     info( '*** Post configure switches and hosts\n')

#     CLI(net)
#     net.stop()

# if __name__ == '__main__':
#     setLogLevel( 'info' )
#     myNetwork()


from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.log import info

if '__main__' == __name__:
    
    net = Mininet(controller=RemoteController)

    c0 = net.addController('c0', ip='134.34.231.214')

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1',protocols="OpenFlow13")
    s2 = net.addSwitch('s2',protocols="OpenFlow13")
    s3 = net.addSwitch('s3',protocols="OpenFlow13")
    s4 = net.addSwitch('s4',protocols="OpenFlow13")
    s5 = net.addSwitch('s5',protocols="OpenFlow13")

    info( '*** Add hosts\n')
    h1 = net.addHost('h1')
    h3 = net.addHost('h3')

    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s5)
    net.addLink(s5, h3)
    net.addLink(s5, s4)
    net.addLink(s4, s3)
    net.addLink(s3, s1)

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])

    # net.startTerms()
    # setLogLevel( 'info' )
    CLI(net)

    net.stop()