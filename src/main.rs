use env_logger::Env;
use log::{error, info};
use std::env;

mod pia;
mod ros;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct PortChangeNotifyConfig {
    webhook_url: Option<String>,
    qbt_url: Option<String>,
    qbt_user: Option<String>,
    qbt_pass: Option<String>,
}

fn configure_connection(
    pia: &mut pia::PrivateInternetAccess,
    ros: &ros::MikrotikApi,
    interface: &str,
    routing_table: &Option<String>,
) -> Result<()> {
    info!("Configuring wireguard interface {}", interface);

    let client_public_key = ros.get_wireguard_public_key(interface)?;
    info!("Public key for {}: {}", interface, client_public_key);

    let wg_config = pia.configure_conection(&client_public_key)?;
    info!(
        "Received wireguard configuration for {}:{}",
        wg_config.server_ip, wg_config.server_port
    );

    info!("Removing old configuration entries on {}", interface);
    ros.remove_interface_ip4s(interface)?;
    ros.remove_wireguard_peers(interface)?;

    info!("Configuring new wireguard connection on {}", interface);
    ros.add_interface_ip4(interface, &wg_config.client_ip)?;
    ros.add_wireguard_peer(
        interface,
        &wg_config.server_public_key,
        &wg_config.server_ip,
        wg_config.server_port,
        "0.0.0.0/0",
        "30s",
    )?;

    if routing_table.is_some() {
        info!("Updating routes to VPN gateway");
        ros.remove_routes(&routing_table.as_ref().unwrap())?;
        ros.add_route(
            &routing_table.as_ref().unwrap(),
            &wg_config.gateway,
            interface,
        )?;
    }

    return Ok(());
}

fn send_port_change_notification(
    new_port: u16,
    notify_config: &PortChangeNotifyConfig,
) -> Result<()> {
    if notify_config.webhook_url.is_some() {
        match ureq::post(notify_config.webhook_url.as_ref().unwrap())
            .send_form(&[("port", &new_port.to_string())])
        {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send port change webhook: {}", e);
                return Err(Box::new(e));
            }
        };
    }

    if notify_config.qbt_url.is_some() {
        let base_url = notify_config.qbt_url.as_ref().unwrap().trim_end_matches('/');
        let login_url = format!("{}/api/v2/auth/login", base_url);
        let logout_url = format!("{}/api/v2/auth/logout", base_url);
        let set_preference_url = format!("{}/api/v2/app/setPreferences", base_url);

        let agent = ureq::agent();

        if notify_config.qbt_user.is_some() && notify_config.qbt_pass.is_some() {
            let response = agent.post(&login_url).set("Referer", base_url).send_form(&[
                ("username", notify_config.qbt_user.as_ref().unwrap()),
                ("password", notify_config.qbt_pass.as_ref().unwrap()),
            ]);

            match response {
                Ok(r) => {
                    if !r.headers_names().contains(&String::from("set-cookie")) {
                        error!("qBittorrent login failed: No auth cookie received");
                        return Err("No auth cookie received".into());
                    }
                }
                Err(e) => {
                    error!("qBittorrent login failed: {}", e);
                    return Err(Box::new(e));
                }
            };
        }

        let payload = format!("{{\"listen_port\": {}}}", new_port);
        let response = agent
            .post(&set_preference_url)
            .send_form(&[("json", &payload)]);

        match response {
            Ok(_) => {}
            Err(e) => {
                error!("qBittorrent port change failed: {}", e);
                return Err(Box::new(e));
            }
        };

        if notify_config.qbt_user.is_some() && notify_config.qbt_pass.is_some() {
            let _ = agent.post(&logout_url).call();
        }
    }

    return Ok(());
}

fn do_port_forwarding(
    pia: &mut pia::PrivateInternetAccess,
    ros: &ros::MikrotikApi,
    interface: &str,
    destination: &str,
    notify_config: &PortChangeNotifyConfig,
) -> Result<()> {
    let mut pf = pia::PortForward {
        port: 0,
        expires_at: chrono::Utc::now(),
        refresh_interval: chrono::Duration::seconds(0),
    };

    let mut notify_sent = false;

    loop {
        if pf.expires_at - chrono::Utc::now() < chrono::Duration::days(1) {
            info!("Requesting new port forward");
            pf = pia.configure_port_forward()?;
            info!("Got forwarded port {} until {}", pf.port, pf.expires_at);
            notify_sent = false;

            ros.remove_nat_rules(interface)?;
            ros.add_nat_rule(interface, "tcp", pf.port, destination)?;
            ros.add_nat_rule(interface, "udp", pf.port, destination)?;
        }

        if !notify_sent {
            match send_port_change_notification(pf.port, notify_config) {
                Ok(_) => {
                    info!("Sent port change notification");
                    notify_sent = true;
                }
                Err(e) => error!("Failed to send port change notification: {}", e),
            };
        }

        std::thread::sleep(pf.refresh_interval.to_std()?);
        info!("Sending port forward keepalive...");
        let result = pia.refresh_port_forward();

        if result.is_err() {
            error!(
                "Failed to send port-forward keepalive: {}",
                result.unwrap_err()
            );
            pf.expires_at = chrono::Utc::now();
        }
    }
}

fn run() -> Result<()> {
    let pia_user = env::var("PIAROS_PIA_USERNAME")?;
    let pia_password = env::var("PIAROS_PIA_PASSWORD")?;
    let pia_region = env::var("PIAROS_PIA_REGION_ID")?;

    let ros_api_url = env::var("PIAROS_ROS_API_URL")?;
    let ros_api_verify_ssl =
        env::var("PIAROS_ROS_API_VERIFY_SSL").unwrap_or("1".to_string()) == "1";
    let ros_user = env::var("PIAROS_ROS_USERNAME")?;
    let ros_password = env::var("PIAROS_ROS_PASSWORD")?;

    let ros_interface = env::var("PIAROS_ROS_INTERFACE")?;
    let ros_table = env::var("PIAROS_ROS_ROUTE_TABLE").ok();
    let ros_pf_dest = env::var("PIAROS_ROS_PORT_FORWARD_TO").ok();

    let notify_config = PortChangeNotifyConfig {
        webhook_url: env::var("PIAROS_ROS_PORT_FORWARD_WEBHOOK").ok(),
        qbt_url: env::var("PIAROS_ROS_PORT_FORWARD_QBT_URL").ok(),
        qbt_user: env::var("PIAROS_ROS_PORT_FORWARD_QBT_USER").ok(),
        qbt_pass: env::var("PIAROS_ROS_PORT_FORWARD_QBT_PASSWORD").ok(),
    };

    let port_forward_enabled = ros_table.is_some() && ros_pf_dest.is_some();

    let mut pia = pia::PrivateInternetAccess::new(&pia_user, &pia_password, &pia_region);
    let ros = ros::MikrotikApi::new(&ros_api_url, &ros_user, &ros_password, ros_api_verify_ssl);

    configure_connection(&mut pia, &ros, &ros_interface, &ros_table)?;

    if !port_forward_enabled {
        info!("Interface configuration complete. Exiting.");
        return Ok(());
    }

    info!(
        "Setting up port forwarding to {}.",
        ros_pf_dest.as_ref().unwrap()
    );
    do_port_forwarding(
        &mut pia,
        &ros,
        &ros_interface,
        ros_pf_dest.as_ref().unwrap(),
        &notify_config,
    )?;
    return Ok(());
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let result = run();
    if result.is_err() {
        error!("Error: {}", result.unwrap_err());
        std::process::exit(-1);
    }
}
