use base64::engine::general_purpose::STANDARD as base64;
use base64::Engine;
use log::info;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use ureq;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod danger {
    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[derive(Deserialize)]
struct NatEntry {
    #[serde(rename = ".id")]
    id: String,

    protocol: String,

    #[serde(rename = "to-addresses")]
    to_address: String,

    #[serde(rename = "to-ports")]
    to_ports: String,

    #[serde(rename = "dst-port")]
    dst_port: String,
}

#[derive(Deserialize)]
struct WgInterfaceEntry {
    #[serde(rename = "public-key")]
    public_key: String,
}

#[derive(Deserialize)]
struct WgPeerEntry {
    #[serde(rename = ".id")]
    id: String,

    #[serde(rename = "endpoint-address")]
    endpoint_address: String,
}

#[derive(Deserialize)]
struct IpEntry {
    #[serde(rename = ".id")]
    id: String,
    address: String,
}

#[derive(Deserialize)]
struct RouteEntry {
    #[serde(rename = ".id")]
    id: String,

    #[serde(rename = "dst-address")]
    dst_address: String,
}

pub struct MikrotikApi {
    base_url: String,
    auth_header: String,
    agent: ureq::Agent,
}

impl MikrotikApi {
    pub fn new(base_url: &str, user: &str, password: &str, verify_ssl: bool) -> Self {
        let credentials = base64.encode(&format!("{}:{}", user, password));
        let auth_header = format!("Basic {}", credentials);

        let mut builder = ureq::AgentBuilder::new();

        if !verify_ssl {
            let mut tls_config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));

            builder = builder.tls_config(Arc::new(tls_config));
        }

        return Self {
            base_url: base_url.to_owned(),
            auth_header,
            agent: builder.build(),
        };
    }

    pub fn get_wireguard_public_key(&self, interface: &str) -> Result<String> {
        let interfaces: Vec<WgInterfaceEntry> =
            self.get_entries("/interface/wireguard", [("name", interface)])?;
        let interface_entry = interfaces
            .iter()
            .next()
            .ok_or(format!("Wiregaurd interface {} not found.", interface))?;
        return Ok(interface_entry.public_key.clone());
    }

    pub fn remove_interface_ip4s(&self, interface: &str) -> Result<()> {
        let addresses: Vec<IpEntry> =
            self.get_entries("/ip/address", [("interface", interface)])?;
        for entry in addresses.iter() {
            info!("Removing interface address: {}", entry.address);
            self.delete_entry("/ip/address", &entry.id)?;
        }
        return Ok(());
    }

    pub fn remove_wireguard_peers(&self, interface: &str) -> Result<()> {
        let peers: Vec<WgPeerEntry> =
            self.get_entries("/interface/wireguard/peers", [("interface", interface)])?;
        for entry in peers.iter() {
            info!("Removing wireguard peer: {}", entry.endpoint_address);
            self.delete_entry("/interface/wireguard/peers", &entry.id)?;
        }
        return Ok(());
    }

    pub fn remove_routes(&self, table: &str) -> Result<()> {
        let routes: Vec<RouteEntry> = self.get_entries("/ip/route", [("routing-table", table)])?;
        for entry in routes.iter() {
            info!("Removing route {} on table {}", entry.dst_address, table);
            self.delete_entry("/ip/route", &entry.id)?;
        }
        return Ok(());
    }

    pub fn remove_nat_rules(&self, interface: &str) -> Result<()> {
        let peers: Vec<NatEntry> =
            self.get_entries("/ip/firewall/nat", [("in-interface", interface)])?;
        for entry in peers.iter() {
            info!(
                "Removing NAT rule: {}/{} -> {}:{}",
                entry.dst_port, entry.protocol, entry.to_address, entry.to_ports
            );
            self.delete_entry("/ip/firewall/nat", &entry.id)?;
        }
        return Ok(());
    }

    pub fn add_nat_rule(
        &self,
        interface: &str,
        protocol: &str,
        port: u16,
        to_address: &str,
    ) -> Result<()> {
        info!(
            "Adding NAT rule: {}/{} -> {}:{}",
            port, protocol, to_address, port
        );
        return self.add_entry(
            "/ip/firewall/nat",
            &json!({
                "in-interface": interface,
                "action": "dst-nat",
                "chain": "dstnat",
                "dst-port": port.to_string(),
                "protocol": protocol,
                "to-addresses": to_address,
                "to-ports": port.to_string()
            }),
        );
    }

    pub fn add_interface_ip4(&self, interface: &str, address: &str) -> Result<()> {
        info!("Adding interface address: {}", address);
        return self.add_entry(
            "/ip/address",
            &json!({"interface": interface, "address": address}),
        );
    }

    pub fn add_wireguard_peer(
        &self,
        interface: &str,
        public_key: &str,
        address: &str,
        port: u16,
        allowed_address: &str,
        persistent_keepalive: &str,
    ) -> Result<()> {
        info!("Adding wireguard peer: {}", address);
        return self.add_entry(
            "/interface/wireguard/peers",
            &json!({
                "interface": interface,
                "public-key": public_key,
                "endpoint-address": address,
                "endpoint-port": &port.to_string(),
                "allowed-address": allowed_address,
                "persistent-keepalive": persistent_keepalive,
            }),
        );
    }

    pub fn add_route(&self, table: &str, dst_address: &str, gateway: &str) -> Result<()> {
        info!(
            "Adding route {} via {} to table {}",
            dst_address, gateway, table
        );
        return self.add_entry(
            "/ip/route",
            &json!({
                "gateway": gateway,
                "dst-address": dst_address,
                "routing-table": table
            }),
        );
    }

    fn build_request(&self, method: &str, path: &str) -> ureq::Request {
        return self
            .agent
            .request(method, &(self.base_url.to_owned() + path))
            .set("Authorization", &self.auth_header);
    }

    fn delete_entry(&self, path: &str, id: &str) -> Result<()> {
        self.build_request("DELETE", &format!("{}/{}", path, id))
            .call()?;
        return Ok(());
    }

    fn get_entries<'a, T: DeserializeOwned, Q: IntoIterator<Item = (&'a str, &'a str)>>(
        &self,
        path: &str,
        filter: Q,
    ) -> Result<Vec<T>> {
        return Ok(self
            .build_request("GET", path)
            .query_pairs(filter)
            .call()?
            .into_json::<Vec<T>>()?);
    }

    fn add_entry<T: Serialize + ?Sized>(&self, path: &str, data: &T) -> Result<()> {
        self.build_request("PUT", path).send_json(&data)?;
        return Ok(());
    }
}
