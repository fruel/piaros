use env_logger::Env;
use log::{error, info};
use std::env;

mod pia;
mod ros;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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

fn do_port_forwarding(
    pia: &mut pia::PrivateInternetAccess,
    ros: &ros::MikrotikApi,
    interface: &str,
    destination: &str,
    notify_webhook_url: &Option<String>,
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

        if !notify_sent && notify_webhook_url.is_some() {
            match ureq::post(notify_webhook_url.as_ref().unwrap())
                .send_form(&[("port", &pf.port.to_string())])
            {
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
    let ros_pf_notify = env::var("PIAROS_ROS_PORT_FORWARD_WEBHOOK").ok();

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
        &ros_pf_notify,
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
