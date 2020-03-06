
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.log import info, setLogLevel

def myNetwork():
     #define a virtual network 
    net = Mininet(controller=RemoteController)

    #add controller to virtual network
    info( '*** Add controller\n')   
    c0 = net.addController('c0', ip='134.34.231.214')

    #add switch
    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', protocols="OpenFlow13")
    s2 = net.addSwitch('s2', protocols="OpenFlow13")
    s3 = net.addSwitch('s3', protocols="OpenFlow13")

    #add host
    info( '*** Add hosts\n')
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')

    #add link between hosts, switches and controllers
    info( '*** Add links\n')
    net.addLink(s1,h1)
    net.addLink(s1,h2)
    net.addLink(s2,h3)
    net.addLink(s3,h4)

    net.addLink(s1,s2)
    net.addLink(s2,s3)

    #build network
    info( '*** Building network ...\n')
    net.build()

    #start running network
    info( '*** Network is running\n')
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    CLI(net)
    net.stop()
if '__main__' == __name__:
    setLogLevel( 'info' )
    myNetwork()
    
    