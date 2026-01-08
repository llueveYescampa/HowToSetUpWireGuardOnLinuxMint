How To Set Up WireGuard on Linux Mint.

## Ref: https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-22-04#step-1-installing-wireguard-and-generating-a-key-pair
## see also:
#
# for server
##  https://www.youtube.com/watch?v=30QufkkRBCI
##  https://totatca.com/code-in-this-video-0012/
# for client
## https://www.youtube.com/watch?v=RT8drPYW4qs
## https://totatca.com/ttc14/
# for Android client
## https://www.smarthomebeginner.com/wireguard-android-client-setup/

    
TO DO ON THE SERVER MACHINE

1.-  Installing WireGuard and Generating a Key Pair

        sudo apt update
        sudo apt-get install  wireguard
    
        wg genkey | sudo tee /etc/wireguard/private.key    
        sudo chmod 600 /etc/wireguard/private.key
        sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key

2.- Choosing IPv4 Addresses
        Choosing an IPv4 Range
        For the purposes of this tutorial we’ll use 10.8.0.0/24

3.- Creating a WireGuard Server Configuration        
        Create a new configuration file
        $ sudo vi /etc/wireguard/wg0.conf
        $ sudo cat /etc/wireguard/wg0.conf
        
        [Interface]
        #PrivateKey = base64_encoded_private_key_goes_here
        PrivateKey = sOp3h5OY7dlS/UgauFr2TyO8qWv+fhKVTZmV34ybIlk=

        ## Address : A private IP address for wg0 interface.
        Address = 10.8.0.1/24

        ## Specify the listening port of WireGuard, I like port 51820, you can change it.
        ListenPort = 51820

        SaveConfig = true

4.- Adjusting the WireGuard Server’s Network Configuration
        in the file /etc/sysctl.conf uncomment the line net.ipv4.ip_forward=1
                
        $ sudo vi /etc/sysctl.conf
        Verify using 'sudo sysctl -p', the output must be: net.ipv6.conf.all.forwarding = 1 
        $ sudo sysctl -p
        sudo sysctl -p
        net.ipv4.ip_forward = 1  <<<---- O.K.
        
5.- Configuring the WireGuard Server’s Firewall 
        find the public network interface of your WireGuard Server using the ip route sub-command
        $ ip route list default
        default via 192.168.1.1 dev wlo1 proto static metric 600
        
        This result shows the interface named wlo1
        
        Add firewall rules to your WireGuard Server, in the /etc/wireguard/wg0.conf
        At the bottom of the file after the SaveConfig = true line, paste the following lines:
        Change the interface name ( in my case wlo1) for what was found using
        the 'ip route list default' command above.
        
        PostUp = ufw route allow in on wg0 out on wlo1
        PostUp = iptables -t nat -I POSTROUTING -o wlo1 -j MASQUERADE
        PreDown = ufw route delete allow in on wg0 out on wlo1
        PreDown = iptables -t nat -D POSTROUTING -o wlo1 -j MASQUERADE
        
        $ sudo vi /etc/wireguard/wg0.conf
        $ sudo cat /etc/wireguard/wg0.conf
        [Interface]
        PrivateKey = sOp3h5OY7dlS/UgauFr2TyO8qWv+fhKVTZmV34ybIlk=

        ## Address : A private IP address for wg0 interface.
        Address = 10.8.0.1/24

        ## Specify the listening port of WireGuard, I like port 51820, you can change it.
        ListenPort = 51820

        SaveConfig = true

        PostUp = ufw route allow in on wg0 out on wlo1
        PostUp = iptables -t nat -I POSTROUTING -o wlo1 -j MASQUERADE
        PreDown = ufw route delete allow in on wg0 out on wlo1
        PreDown = iptables -t nat -D POSTROUTING -o wlo1 -j MASQUERADE        
        
        $ sudo ufw allow 51820/udp
        $ sudo ufw allow OpenSSH  <<-- in case you do not gave port 22
        $ sudo ufw reload
        
        $ sudo ufw status | grep 51820
        51820/udp                  ALLOW       Anywhere                  
        51820/udp (v6)             ALLOW       Anywhere (v6)                  

        $ sudo ufw status | grep OpenSSH
        OpenSSH                    ALLOW       Anywhere                  
        OpenSSH (v6)               ALLOW       Anywhere (v6)    

6.- Starting the WireGuard Server
        While you could manually use the wg command to create the tunnel every time you want to use the VPN, 
        doing so is a manual process that becomes repetitive and error prone. 
        
        WireGuard can be configured to run as a systemd service using its built-in wg-quick script. 
        Using a systemd service means that you can configure WireGuard to start up at boot.
        
        $ sudo systemctl enable wg-quick@wg0.service
        Created symlink /etc/systemd/system/multi-user.target.wants/wg-quick@wg0.service → /lib/systemd/system/wg-quick@.service.
        
        Now start the service:
        $ sudo systemctl start wg-quick@wg0.service
        
        Double check that the WireGuard service is active with the following command.
        $ sudo systemctl status wg-quick@wg0.service
        ● wg-quick@wg0.service - WireGuard via wg-quick(8) for wg0
             Loaded: loaded (/lib/systemd/system/wg-quick@.service; enabled; vendor preset: enabled)
             Active: active (exited) since Sat 2024-06-29 17:38:29 CDT; 12s ago                         <<<--- see the active here
               Docs: man:wg-quick(8)
                     man:wg(8)
                     https://www.wireguard.com/
                     https://www.wireguard.com/quickstart/
                     https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8
                     https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8
            Process: 18222 ExecStart=/usr/bin/wg-quick up wg0 (code=exited, status=0/SUCCESS)
           Main PID: 18222 (code=exited, status=0/SUCCESS)

        Jun 29 17:38:29 blackEngineering systemd[1]: Starting WireGuard via wg-quick(8) for wg0...
        Jun 29 17:38:29 blackEngineering wg-quick[18222]: [#] ip link add wg0 type wireguard
        Jun 29 17:38:29 blackEngineering wg-quick[18222]: [#] wg setconf wg0 /dev/fd/63
        Jun 29 17:38:29 blackEngineering wg-quick[18222]: [#] ip -4 address add 10.8.0.1/24 dev wg0
        Jun 29 17:38:29 blackEngineering wg-quick[18222]: [#] ip link set mtu 1420 up dev wg0
        Jun 29 17:38:29 blackEngineering wg-quick[18222]: [#] ufw route allow in on wg0 out on wlo1
        Jun 29 17:38:29 blackEngineering wg-quick[18274]: Rule added
        Jun 29 17:38:29 blackEngineering wg-quick[18274]: Rule added (v6)
        Jun 29 17:38:29 blackEngineering wg-quick[18222]: [#] iptables -t nat -I POSTROUTING -o wlo1 -j MASQUERADE
        Jun 29 17:38:29 blackEngineering systemd[1]: Finished WireGuard via wg-quick(8) for wg0.
        
        To stop the service:
        $ sudo systemctl stop wg-quick@wg0.service
        
        Double check that the WireGuard service is inactive with the following command.
        $ sudo systemctl status wg-quick@wg0.service
        ● wg-quick@wg0.service - WireGuard via wg-quick(8) for wg0
             Loaded: loaded (/lib/systemd/system/wg-quick@.service; enabled; vendor preset: enabled)
             Active: inactive (dead) since Sat 2024-06-29 17:40:06 CDT; 1min 34s ago                    <<<--- see the inactive here
               Docs: man:wg-quick(8)
                     man:wg(8)
                     https://www.wireguard.com/
                     https://www.wireguard.com/quickstart/
                     https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8
                     https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8
            Process: 18222 ExecStart=/usr/bin/wg-quick up wg0 (code=exited, status=0/SUCCESS)
            Process: 18487 ExecStop=/usr/bin/wg-quick down wg0 (code=exited, status=0/SUCCESS)
           Main PID: 18222 (code=exited, status=0/SUCCESS)

        Jun 29 17:38:29 blackEngineering systemd[1]: Finished WireGuard via wg-quick(8) for wg0.
        Jun 29 17:40:05 blackEngineering systemd[1]: Stopping WireGuard via wg-quick(8) for wg0...
        Jun 29 17:40:05 blackEngineering wg-quick[18487]: [#] ufw route delete allow in on wg0 out on wlo1
        Jun 29 17:40:05 blackEngineering wg-quick[18510]: Rule deleted
        Jun 29 17:40:05 blackEngineering wg-quick[18510]: Rule deleted (v6)
        Jun 29 17:40:05 blackEngineering wg-quick[18487]: [#] iptables -t nat -D POSTROUTING -o wlo1 -j MASQUERADE
        Jun 29 17:40:05 blackEngineering wg-quick[18573]: [#] wg showconf wg0
        Jun 29 17:40:06 blackEngineering wg-quick[18487]: [#] ip link delete dev wg0
        Jun 29 17:40:06 blackEngineering systemd[1]: wg-quick@wg0.service: Succeeded.
        Jun 29 17:40:06 blackEngineering systemd[1]: Stopped WireGuard via wg-quick(8) for wg0.
        
        
TO DO ON THE WIREGUARD PEER

1.-  Installing WireGuard and Generating a Key Pair

        sudo apt update
        sudo apt-get install  wireguard
    
        wg genkey | sudo tee /etc/wireguard/private.key    
        sudo chmod 600 /etc/wireguard/private.key
        sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key

2.- Configuring a Peer to Route All Traffic Over the Tunnel
        if you would like to send all your peer’s traffic over the VPN and use the WireGuard Server 
        as a gateway for all traffic, then you can use 0.0.0.0/0, which represents the entire IPv4
        
        Determine the IP address that the system uses as its default gateway. Run the following ip route command:
        
        $ ip route list table main default
        default via 192.168.1.1 dev wlp3s0 proto static metric 600
        
        Note the gateway’s highlighted IP address 192.168.1.1 for later use, and device wlp3s0.
        Your device name may be different. 
        
        Next find the public IP for the system by examining the device with the ip address show command:
        $ ip -brief address show wlp3s0
        wlp3s0           UP             192.168.1.114/24 fe80::7d92:cdc8:fef2:1133/64
        
        In this example output, the highlighted 192.168.1.114 IP (without the trailing /24) is the public address 
        that is assigned to the wlp3s0 device that you’ll need to add to the WireGuard configuration.

3.- Creating the WireGuard Peer’s Configuration File
    You will need a few pieces of information for the configuration file:
    The base64 encoded private key that you generated on the peer. (aBETnA3PoTPZhBWBB6MP1GibX+KEuIH1cksnf2xVWmQ=)
    The IPv4 and IPv6 address ranges that you defined on the WireGuard Server. (10.8.0.0/24)
    The base64 encoded public key from the WireGuard Server. (Y5IavP6apSJeA3dYccsEmnbY7adB3NjWVS7Bf/2zcws=)
    The public IP address and port number of the WireGuard Server. (192.168.1.101:5182)
    

        Create a new configuration file
        $ sudo vi /etc/wireguard/wg0.conf
        
        efblack@blackMagic:~$ sudo cat /etc/wireguard/wg0.conf
        [Interface]
        ### PrivateKey_of_the_Client
        PrivateKey = aBETnA3PoTPZhBWBB6MP1GibX+KEuIH1cksnf2xVWmQ=
        
        ### IP VPN for the Client
        Address = 10.8.0.2/24

        ### DNS Server
        #DNS = 8.8.8.8, 8.8.4.4
        #DNS = 192.168.1.1
        
        PostUp = ip rule add table 200 from 192.168.1.114
        PostUp = ip route add table 200 default via 192.168.1.1
        PreDown = ip rule delete table 200 from 192.168.1.114
        PreDown = ip route delete table 200 default via 192.168.1.1

        [Peer]
        PublicKey = Y5IavP6apSJeA3dYccsEmnbY7adB3NjWVS7Bf/2zcws=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 192.168.1.101:51820
        #Endpoint = 140.177.158.32:51820
        #Endpoint = blackfamily.ddns.net:51820

4.-  Adding the Peer’s Public Key to the WireGuard Server
        ensure that you have a copy of the base64 encoded public key for the WireGuard Peer by running:
        
        sudo cat /etc/wireguard/public.key
        UQ2KqzRA9bLHarBnBL6zj0PQUlKe74cgMv8T1nyIbgU=
        
        Now log into the WireGuard server, and run the following command:
        
        $ sudo wg set wg0 peer UQ2KqzRA9bLHarBnBL6zj0PQUlKe74cgMv8T1nyIbgU= allowed-ips 10.8.0.2
        
        Once you have run the command to add the peer, check the status of the tunnel on the 
        server using the wg command:
        $ sudo wg
        
        $ sudo wg
        interface: wg0
          public key: Y5IavP6apSJeA3dYccsEmnbY7adB3NjWVS7Bf/2zcws=
          private key: (hidden)
          listening port: 51820

        peer: UQ2KqzRA9bLHarBnBL6zj0PQUlKe74cgMv8T1nyIbgU=
          allowed ips: 10.8.0.2/32
          
5.- Connecting the WireGuard Peer to the Tunnel

        Now that your server and peer are both configured to support your choice of IPv4
        it is time to connect the peer to the VPN tunnel.
        
        $ sudo wg-quick up wg0
        [#] ip link add wg0 type wireguard
        [#] wg setconf wg0 /dev/fd/63
        [#] ip -4 address add 10.8.0.2/24 dev wg0
        [#] ip link set mtu 1420 up dev wg0
        [#] ip rule add table 200 from 192.168.1.114
        [#] ip route add table 200 default via 192.168.1.1

        You can check the status of the tunnel on the peer using the wg command:
        
        $ sudo wg
        interface: wg0
          public key: UQ2KqzRA9bLHarBnBL6zj0PQUlKe74cgMv8T1nyIbgU=
          private key: (hidden)
          listening port: 47506
          fwmark: 0xca6c

        peer: Y5IavP6apSJeA3dYccsEmnbY7adB3NjWVS7Bf/2zcws=
          endpoint: 192.168.1.101:51820
          allowed ips: 0.0.0.0/0
          latest handshake: 1 minute, 12 seconds ago
          transfer: 6.48 KiB received, 6.83 KiB sent
