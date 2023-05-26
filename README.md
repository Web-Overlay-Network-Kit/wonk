# the Overlay Network Kit
A cluster of libraries useful for building overlay networks in the browser.

- revproxy
- peercon
- overlay-client
- overlay-node

## revproxy
revproxy is a WebRTC reverse proxy library.  It commits crimes against the TURN spec in order to facilitate "unsignalled" WebRTC connections.

What does "unsignalled" mean?  It means that a "server" browser can connect to the revproxy and receive a long-lived address.  It can then give this address to many "client" browsers.  A "client" browser can use the information from the address to construct an RTCPeerConnection which will connect through the revproxy to the "server" browser.  The "client" sends zero signalling messages.

The way this works is that the revproxy detects the incoming connection from the "client" and sends a message to the "server" with enough information to reply to the incoming connection.  As always, the WebRTC connection is end-to-end encrypted and in this case the two ends are the "client" and the "server" - the proxy can't see any of the data.

Lastly, after a few seconds / kilobytes the revproxy stops forwarding packets between the "client" and "server" this tricks the browsers into thinking that they should try other connection paths which in ~85% of cases will migrate to a direct P2P connection between the peers.  Once the connection has been migrated off the revproxy, then the revproxy could die without affecting the connection.

This isn't a new capability - LibP2P has proxied connections - but it is new in that the connection is 100% WebRTC from the very beginning.  This means that your overlay network can use full WebRTC features without thinking about the limits of your secondary protocol (which is usually WebSocket or now WebTransport).  You can use multiple datachannels, audio / video, connection stats, etc.  I believe that this will simplify the process of building overlay networks in the browser.

## peercon
peercon is an extended RTCPeerConnection.  It's a little bit like simple-peer in that it handles renegotiation automatically, but it also supports making "unsignalled" connections using addresses.  For non-address connections, it can reduce the number of signalling messages to always be 2 (1 from each peer).  In the future, it may have built-in support for "peer-exchange" / single-hop discovery.

## bitters
bitters is a library to help with building custom APIs using cross-origin iframes.

### Benefits
Using a cross-origin implementation of your overlay network means that multiple websites can access your network without creating multiple nodes in your network, instead all the website access your network through a single node (running in multiple iframes).  It means you can persist / update a single seed list for your network.  It means that if the user is already bootstrapped into the network from using one website and then they open another website that uses your network, they won't re-bootstrap into the network.  Instead, you can reuse / aggregate the connections you already have or maybe redistribute them among the new iframes.

These benefits come without introducing a central point of failure.  The custom-protocol handler means that each user can set their prefered implementation / node software to access your network, but different users can use different implementations while remaining interoperable.  WebRTC has always been origin agnostic.  You just don't see this often, however, because most sites use a central signalling server.  The peercon messages and addresses are protocol driven and can be used from any origin.

Having multiple node software implementations should improve your network's resilience to censorship and denial of service attacks against your hosting servers.  Furthermore, your node-software should be purely static files so you can add a service worker with offline support.  In this scenario, users of your network can continue interacting even if your hosting servers go offline.  The only servers that your network would rely on would be revproxy servers and savy users can host their own revproxy.  And if your node software is static files, it's easy and cheep for you or others to migrate your software to new hosting to recover from an attack.  If WebBundles or something similar comes back, then there may even be a future where users can share your node-software with each other via bluetooth while your static servers are offline.

### Challenges
It's rough.  To make this work properly you need to write a multi-threaded implementation of your node software.  Multi-threaded because your connections are being held inside multiple iframes embedded into multiple pages.  Yet together these iframes need to act as a single node.  You'll need to use a combination of WebLocks, SharedWorkers, BroadcastChannels, and definitely IndexedDB in order to coordinate the multiple iframe-threads of your node-software.  Your threads can die - every time the user closes a page, the iframe embedded in it will also die which means redistributing WebRTC connections to your remaining frames.  There's a user-interface challenge, because in order to access cross-origin storage you'll need to prompt the user for permission, and that permission request will roughly say, "Are you ok with node-software.[yourdomain].org to track your activity on this site?" even if you don't use this cross-origin communication for tracking.  I don't really know how to build up that user trust.  But I think it's worth it.  Good luck.
