use base64::engine::general_purpose::STANDARD as base64;
use base64::Engine;
use chrono::prelude::*;
use log::info;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use ureq;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const PIA_PF_API_PORT: u16 = 19999;
const PIA_LOGIN_URL: &str = "https://www.privateinternetaccess.com/api/client/v2/token";
const PIA_SERVER_LIST_URL: &str = "https://serverlist.piaservers.net/vpninfo/servers/v6";

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Deserialize)]
struct ServerGroup {
    //name: String,
    ports: Vec<u16>,
}

#[derive(Deserialize, Clone)]
struct Server {
    ip: String,
    cn: String,
}

#[derive(Deserialize)]
struct ServerRegion {
    id: String,
    //name: String,
    //country: String,
    //auto_region: bool,
    //dns: String,
    //port_forward: bool,
    //geo: bool,
    //offline: bool,
    servers: HashMap<String, Vec<Server>>,
}

#[derive(Deserialize)]
struct ServerListResponse {
    groups: HashMap<String, Vec<ServerGroup>>,
    regions: Vec<ServerRegion>,
}

#[derive(Deserialize)]
struct AddKeyResponse {
    //status: String,
    server_key: String,
    //server_port: u16,
    //server_ip: String,
    server_vip: String,
    peer_ip: String,
    //peer_pubkey: String,
    dns_servers: Vec<String>,
}

#[derive(Deserialize)]
struct GetSignatureResponse {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
struct PayloadData {
    expires_at: DateTime<Utc>,
    port: u16,
}

#[derive(Deserialize)]
struct PortForwardConfig {
    payload: String,
    signature: String,
    expires_at: DateTime<Utc>,
}

pub struct InterfaceConfiguration {
    pub server_public_key: String,
    pub server_port: u16,
    pub server_ip: String,
    pub gateway: String,
    pub client_ip: String,
    pub dns_servers: Vec<String>,
}

pub struct PortForward {
    pub port: u16,
    pub expires_at: DateTime<Utc>,
    pub refresh_interval: chrono::Duration,
}

pub struct PrivateInternetAccess {
    username: String,
    password: String,
    auth_token: String,
    auth_token_expiration: DateTime<Utc>,
    server_region: String,
    server: Option<Server>,
    port_forward_config: Option<PortForwardConfig>,
}

impl PrivateInternetAccess {
    pub fn new(username: &str, password: &str, server_region: &str) -> Self {
        return Self {
            username: username.to_owned(),
            password: password.to_owned(),
            auth_token: String::new(),
            auth_token_expiration: Utc::now(),
            server_region: server_region.to_owned(),
            server: None,
            port_forward_config: None,
        };
    }

    fn get_auth_token(&mut self) -> Result<&str> {
        if Utc::now() < self.auth_token_expiration {
            return Ok(&self.auth_token);
        }

        let response: LoginResponse = ureq::post(PIA_LOGIN_URL)
            .send_form(&[("username", &self.username), ("password", &self.password)])?
            .into_json()?;

        self.auth_token = response.token;
        self.auth_token_expiration = Utc::now() + chrono::Duration::days(1);

        info!("Fetched new PIA auth token.");
        return Ok(&self.auth_token);
    }

    fn get_server_list(&self) -> Result<ServerListResponse> {
        let response = ureq::get(PIA_SERVER_LIST_URL).call()?.into_string()?;
        let first_line = response
            .lines()
            .next()
            .ok_or("Invalid server list response format")?;
        return Ok(serde_json::from_str::<ServerListResponse>(first_line)?);
    }

    fn get_port(&self, group: &str) -> Result<u16> {
        let server_list = self.get_server_list()?;
        let group_data = server_list
            .groups
            .get(group)
            .ok_or(format!("Group {} not found.", group,))?;
        let ports = &group_data
            .get(0)
            .ok_or(format!("No entry in group {}.", group))?
            .ports;
        return Ok(ports
            .get(0)
            .ok_or(format!("No ports in group {}.", group))?
            .to_owned());
    }

    fn find_servers(&self, region: &str, group: &str) -> Result<Vec<Server>> {
        let server_list = self.get_server_list()?;
        let region_data = server_list
            .regions
            .iter()
            .find(|&r| r.id == region)
            .ok_or(format!("Region {} not found", region))?;
        let servers = region_data
            .servers
            .get(group)
            .ok_or(format!("Group {} not found in region {}.", group, region))?;
        return Ok(servers.to_vec());
    }

    fn create_agent(
        &self,
        server_name: &str,
        server_ip: &str,
        server_port: u16,
    ) -> Result<ureq::Agent> {
        let parsed_ip: Ipv4Addr = server_ip.parse()?;
        let socket = SocketAddr::new(IpAddr::V4(parsed_ip), server_port);
        let dns_name = String::from(server_name);

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(&[include_bytes!("../ca.rsa.4096.der")]);

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        return Ok(ureq::AgentBuilder::new()
            .resolver(move |addr: &str| match addr {
                _ if addr == format!("{}:{}", dns_name, server_port) => Ok(vec![socket]),
                addr => addr.to_socket_addrs().map(Iterator::collect),
            })
            .tls_config(Arc::new(tls_config))
            .build());
    }

    pub fn configure_conection(
        &mut self,
        client_public_key: &str,
    ) -> Result<InterfaceConfiguration> {
        let available_servers = self.find_servers(&self.server_region, "wg")?;
        let server = available_servers.iter().next().ok_or(format!(
            "No server found for region: {}",
            self.server_region
        ))?;

        info!("Using server {} at {}", server.cn, server.ip);

        let port = self.get_port("wg")?;
        let agent = self.create_agent(&server.cn, &server.ip, port)?;
        let url = format!("https://{}:{}/addKey", server.cn, port);

        let token = self.get_auth_token()?;
        let response: AddKeyResponse = agent
            .get(&url)
            .query("pt", token)
            .query("pubkey", client_public_key)
            .call()?
            .into_json()?;

        self.server = Some(Server {
            ip: response.server_vip.clone(),
            cn: server.cn.clone(),
        });
        return Ok(InterfaceConfiguration {
            server_public_key: response.server_key,
            server_port: port,
            server_ip: server.ip.clone(),
            gateway: response.server_vip,
            client_ip: response.peer_ip,
            dns_servers: response.dns_servers,
        });
    }

    pub fn configure_port_forward(&mut self) -> Result<PortForward> {
        let server = match &self.server {
            None => return Err("Connection not configured".into()),
            Some(s) => s,
        };

        let agent = self.create_agent(&server.cn, &server.ip, PIA_PF_API_PORT)?;
        let url = format!("https://{}:{}/getSignature", server.cn, PIA_PF_API_PORT);
        let token = self.get_auth_token()?;

        let response: GetSignatureResponse =
            agent.get(&url).query("token", token).call()?.into_json()?;

        let decoded_payload = String::from_utf8(base64.decode(&response.payload)?)?;
        let payload_details: PayloadData = serde_json::from_str(&decoded_payload)?;

        self.port_forward_config = Some(PortForwardConfig {
            payload: response.payload,
            signature: response.signature,
            expires_at: payload_details.expires_at,
        });

        self.refresh_port_forward()?;
        return Ok(PortForward {
            port: payload_details.port,
            expires_at: payload_details.expires_at,
            refresh_interval: chrono::Duration::minutes(15),
        });
    }

    pub fn refresh_port_forward(&mut self) -> Result<()> {
        let server = match &self.server {
            None => return Err("Connection not configured".into()),
            Some(s) => s,
        };
        let pf_config = match &self.port_forward_config {
            None => return Err("Port forwarding not configured".into()),
            Some(p) => p,
        };

        if Utc::now() >= pf_config.expires_at {
            return Err("Requested port forward expired".into());
        }

        let agent = self.create_agent(&server.cn, &server.ip, PIA_PF_API_PORT)?;
        let url = format!("https://{}:{}/bindPort", server.cn, PIA_PF_API_PORT);

        agent
            .get(&url)
            .query("payload", &pf_config.payload)
            .query("signature", &pf_config.signature)
            .call()?;

        return Ok(());
    }
}
