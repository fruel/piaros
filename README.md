# Piaros - PIA configurator for ROS
Piaros is a small container for Mikrotik RouterOS devices that configures Wireguard connections to Private Internet Access VPN servers incl. setting up port forwarding.

Features:
* Automatically configure Wireguard interface
* Request & configure port forwarding incl. DSTNAT
* Notify other services via webhook about port changes
* Total container size less than 1MB

> [!NOTE]
> Piaros will only do the basic interface configuration and optionally setup a DSTNAT rule for port forwarding incoming traffic. Any additional routing and firewall settings have to be configured manually.

# Prerequisites

## RouterOS user account
Create a new user that will be used for all configuration tasks:
```
/user/group/add name=piaros policy=api,rest-api,read,write
/user/add name=piaros group=piaros password="something secure"
```

## RouterOS REST API
Enable the Webfig/REST API service:

> [!CAUTION]
> Make sure to limit access to this service in a way that is appropriate for your network! If it is only used by Piaros, you can limit access to the container IP like this `/ip/service/set www disabled=no address=172.17.0.2/32` and/or create appropriate rules in `/ip/firewall/filter`

```
/ip/service/set www disabled=no
or
/ip/service/set www-ssl disabled=no
```

> [!IMPORTANT]
> The `www-ssl` service will also need a certificate configured. Instructions for certificates can be found in the [MirkoTik documentation](https://help.mikrotik.com/docs/display/ROS/Certificates).

## Wireguard interface
Create a new Wireguard interface:
```
/interface/wireguard/add name=wg-pia
```

# Basic Configuration (Container running on RouterOS)

* Install and enable container support according to the [MirkoTik documentation](https://help.mikrotik.com/docs/display/ROS/Container).
* Configure container networking:
  ```
  /interface/veth/add name=veth-piaros address=172.17.0.2/24 gateway=172.17.0.1
  /interface/bridge/add name=containers
  /ip/address/add address=172.17.0.1/24 interface=containers
  /interface/bridge/port add bridge=containers interface=veth-piaros
  ```
  Adjust this as needed for your network (IP ranges, NAT, firewall settings, ...). Piaros will need internet access to retrieve the configuration and access to the `www/ww-ssl` service.
* Add environment variables
  ```
  /container/envs/add name=piaros key=PIAROS_PIA_USERNAME value=p1234567
  /container/envs/add name=piaros key=PIAROS_PIA_PASSWORD value=...
  /container/envs/add name=piaros key=PIAROS_PIA_REGION_ID value=us_new_york_city
  /container/envs/add name=piaros key=PIAROS_ROS_API_URL value="http://172.17.0.1/rest"
  /container/envs/add name=piaros key=PIAROS_ROS_USERNAME value=piaros
  /container/envs/add name=piaros key=PIAROS_ROS_PASSWORD value=...
  /container/envs/add name=piaros key=PIAROS_ROS_INTERFACE value=wg-pia
  ```
* Upload the container image `.tar` file to your device (make sure to use the proper architecture for your device and that there is enough free storage!)
* Create the container
  ```
  /container/add file=piaros-arm64.tar interface=veth-piaros envlist=piaros root-dir=disk1/piaros hostname=piaros logging=yes dns=1.1.1.1 start-on-boot=yes
  ```
* Start the container
  ```
  /container/start 0
  ```

If port forwarding is not enabled, the container will exit after the Wiregaurd connection is configured.

# Basic Configuration (Container running on another machine)
Piaros can also run on another machine as long as it can reach the RouterOS API. Just use docker or docker-compose to run it:
```
docker run -it --rm \
-e PIAROS_PIA_USERNAME="p1234567" \
-e PIAROS_PIA_PASSWORD="..." \
-e PIAROS_PIA_REGION_ID="us_new_york_city" \
-e PIAROS_ROS_API_URL="https://172.17.0.1/rest" \
-e PIAROS_ROS_API_VERIFY_SSL=0 \
-e PIAROS_ROS_USERNAME="piaros" \
-e PIAROS_ROS_PASSWORD="..." \
-e PIAROS_ROS_INTERFACE="wg-pia" \
ghcr.io/fruel/piaros:latest-amd64
```

# Port Forwarding
Private Internet Access has the option to request a forwarded port for incoming connections. A port forward is valid for ~2 months and regular keep-alive message need to be sent to keep it active.

When port forwarding is enabled, Piaros will do the following:
* Request a new port forward from the VPN gateway
* Add DSTNAT firewall rules for TCP & UDP
* Send keep-alive messages to the VPN gateway every 15min
* Request a new port forward if the old one expires 
* (optional) Send a notification via HTTP POST to tell other services about the port number

## Configuring port forwarding

* **Create routing table:**

   To configure port-forwarding, Piaros needs to connect to the VPN gateway through the Wireguard interface. For this, create a new routing table that is used for connections from the container. Piaros will add a /32 route to direct connections to the VPN gateway out the Wireguard interface instead of using the normal default gateway:
   ```
   /routing table add fib name=piaros
   /routing rule add action=lookup src-address=172.17.0.2/32 table=piaros
   ```
   
* **Add container environment variables:**
  ```
  /container/envs/add key=PIAROS_ROS_ROUTE_TABLE name=piaros value=piaros
  /container/envs/add key=PIAROS_ROS_PORT_FORWARD_TO name=piaros value=192.168.88.100
  ```
* **(optional) Enable notification webhook:**
  ```
  /container/envs/add key=PIAROS_ROS_PORT_FORWARD_WEBHOOK name=piaros value=http://192.168.88.100:1234/
  ```

  On the destination machine, a script like this can be used to reconfigure any services that need to listen on the forwarded port:
  ```python
  from http.server import BaseHTTPRequestHandler, HTTPServer
  from email.message import EmailMessage
  import urllib
  import json

  class ConfigServer(BaseHTTPRequestHandler):
      def do_POST(self):
          vars = self.parse_post()
          self.send_response(204, "No Content")
          self.end_headers()

          if b"port" in vars:
              port = int(vars[b'port'][0])
              self.log_message(f"New port: {port}")
              
              # TODO: reconfigure & restart services

      def parse_post(self):
          msg = EmailMessage()
          msg['content-type'] = self.headers.get('content-type')
          if msg.get_content_type() == 'application/x-www-form-urlencoded':
              length = int(self.headers.get('content-length'))
              return urllib.parse.parse_qs(self.rfile.read(length))
          return {}

  if __name__ == "__main__":        
      server = HTTPServer(("0.0.0.0", 1234), ConfigServer)
      try:
          server.serve_forever()
      except KeyboardInterrupt:
          pass
      server.server_close()
  ```

# Environment Variables
All configuration options are passed via environment variables.

|                                 |                                                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PIAROS_PIA_USERNAME             | PIA account username                                                                                                                                                       |
| PIAROS_PIA_PASSWORD             | PIA account password                                                                                                                                                       |
| PIAROS_PIA_REGION_ID            | PIA server region to use. See the `id` fields in the [Server List JSON](https://serverlist.piaservers.net/vpninfo/servers/v6) for available options (e.g. `uk_manchester`) |
| PIAROS_ROS_API_URL              | API URL of your RouterOS device e.g. `http://192.168.88.1/rest`                                                                                                            |
| PIAROS_ROS_API_VERIFY_SSL       | Whether to verify the SSL certificate if the API URL uses HTTPS (`0` or `1`, default is `1`)                                                                               |
| PIAROS_ROS_USERNAME             | RouterOS API username                                                                                                                                                      |
| PIAROS_ROS_PASSWORD             | RouterOS API password                                                                                                                                                      |
| PIAROS_ROS_INTERFACE            | Name of the Wireguard interface to configure                                                                                                                               |
| PIAROS_ROS_ROUTE_TABLE          | (optional) Name of the routing table used during port forwarding setup                                                                                                     |
| PIAROS_ROS_PORT_FORWARD_TO      | (optional) Destination address of the port forward DSTNAT rule                                                                                                              |
| PIAROS_ROS_PORT_FORWARD_WEBHOOK | (optional) Webhook to call when the forwarded port changes                                                                                                                 |

