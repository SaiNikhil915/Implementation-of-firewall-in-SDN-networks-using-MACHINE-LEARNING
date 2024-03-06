from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

net = Mininet(controller=RemoteController)

# Add hosts
h1 = net.addHost('h1', ip='10.0.0.1')
h2 = net.addHost('h2', ip='10.60.50.48')
h3 = net.addHost('h3', ip='10.60.50.47')

# Add switches
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
s4 = net.addSwitch('s4')
s5 = net.addSwitch('s5')

# Add links
net.addLink(s1, s2)
net.addLink(s1, s3)
net.addLink(s3, s4)
net.addLink(s4, s5)
net.addLink(s2, s5)
net.addLink(s5, h3)
net.addLink(s1, h1)
net.addLink(s2, h2)

# Add controller
c0 = net.addController('c0', ip='127.0.0.1', port=6653)

# Build the network
net.build()

# Set the controller for each switch
s1.start([c0])
s2.start([c0])
s3.start([c0])
s4.start([c0])
s5.start([c0])

# Start the network
net.start()

# Run the Mininet CLI
CLI(net)

# Stop the network when the CLI is closed
net.stop()
