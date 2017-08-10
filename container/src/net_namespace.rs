extern crate libc;

use self::libc::pid_t;
use std;
use std::io;
use std::process::Command;

// Parent side configuration for a network namespace

#[derive(Debug)]
pub enum Error {
    AddingVethInterfaces(io::Error),
    AddingInterfaceToBridge(io::Error),
    EnablingBridgeInterface(io::Error),
    EnablingContainerVeth(io::Error),
    EnablingHostVeth(io::Error),
    EnablingLoopback(io::Error),
    EnablingV4Forward(io::Error),
    Io(io::Error),
    NetNamespaceDeviceSetupFailed,
    SettingAcceptRule(io::Error),
    SettingDefaultRoute(io::Error),
    SettingForwardRule(io::Error),
    SettingInterfaceAddress(io::Error),
    SettingNatRule(io::Error),
    SettingNetNamespace(io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

fn enable_device(dev: &str) -> std::result::Result<(), io::Error> {
    Command::new("ip").args(&["link", "set", dev, "up"])
        .status()?;
    Ok(())
}

pub trait NetNamespace {
    fn configure_for_pid(&self, pid: pid_t) -> Result<()>;
    fn configure_in_child(&self) -> Result<()>;
}

pub struct NatNetNamespace {
    upstream_ifaces: Vec<String>,
    ip_addr: String, // ip address of the host-side interface for NAT
    namespace_addr: Option<String>, // ip address of the container-side interface for NAT
}

impl NatNetNamespace {
    pub fn new(upstream_ifaces: Vec<String>,
               ip_addr: String,
               namespace_addr: Option<String>)
               -> Self {
        NatNetNamespace {
            upstream_ifaces: upstream_ifaces,
            ip_addr: ip_addr,
            namespace_addr: namespace_addr,
        }
    }
}

impl NetNamespace for NatNetNamespace {
    fn configure_for_pid(&self, pid: pid_t) -> Result<()> {
        // Crate a veth pair, set up masquerade for one port, give the other to
        // the pid's net namespace.
        // TODO - don't hard-code veth0,veth1
        Command::new("ip").args(&["link", "add", "veth0", "type", "veth", "peer", "name", "veth1"])
            .status()
            .map_err(Error::AddingVethInterfaces)?;
        let mut host_ip_mask = self.ip_addr.clone();
        host_ip_mask.push_str("/24");
        Command::new("ip").args(&["addr", "add", &host_ip_mask, "dev", "veth0"])
            .status()
            .map_err(Error::SettingInterfaceAddress)?;
        Command::new("ip").args(&["link", "set", "veth0", "up"])
            .status()
            .map_err(Error::EnablingHostVeth)?;
        Command::new("ip").args(&["link", "set", "veth1", "up"])
            .status()
            .map_err(Error::EnablingContainerVeth)?;
        Command::new("ip").args(&["link", "set", "veth1", "netns", &pid.to_string()])
            .status()
            .map_err(Error::SettingNetNamespace)?;
        // iptables nat masquerade setup
        for iface in self.upstream_ifaces.iter() {
            Command::new("iptables")
                .args(&["-t", "nat", "-A", "POSTROUTING", "-o", &iface, "-j", "MASQUERADE"])
                .status()
                .map_err(Error::SettingNatRule)?;
            Command::new("iptables").args(&["-A",
                        "FORWARD",
                        "-i",
                        "veth0",
                        "-o",
                        &iface,
                        "-m",
                        "state",
                        "--state",
                        "RELATED,ESTABLISHED",
                        "-j",
                        "ACCEPT"])
                .status()
                .map_err(Error::SettingForwardRule)?;
            Command::new("iptables")
                .args(&["-A", "FORWARD", "-i", "veth0", "-o", iface, "-j", "ACCEPT"])
                .status()
                .map_err(Error::SettingAcceptRule)?;
        }
        Command::new("sysctl").arg("net.ipv4.ip_forward=1")
            .status()
            .map_err(Error::EnablingV4Forward)?;

        Ok(())
    }

    fn configure_in_child(&self) -> Result<()> {
        if let Some(ref namespace_addr) = self.namespace_addr {
            let mut container_ip_mask = namespace_addr.clone();
            container_ip_mask.push_str("/24");
            Command::new("ip").args(&["addr", "add", &container_ip_mask, "dev", "veth1"])
                .status()
                .map_err(Error::SettingInterfaceAddress)?;
            Command::new("ip").args(&["link", "set", "veth1", "up"])
                .status()
                .map_err(Error::EnablingContainerVeth)?;
            Command::new("ip").args(&["route", "add", "default", "via", &self.ip_addr])
                .status()
                .map_err(Error::SettingDefaultRoute)?;
        }
        enable_device("lo").map_err(Error::EnablingLoopback)?;
        Ok(())
    }
}

pub struct BridgedNetNamespace {
    bridge_name: String,
    upstream_iface: String,
    default_route_ip: String,
    namespace_ip: String,
}

impl BridgedNetNamespace {
    pub fn new(bridge_name: String,
               upstream_iface: String,
               default_route_ip: String,
               namespace_ip: String)
               -> Self {
        BridgedNetNamespace {
            bridge_name: bridge_name,
            upstream_iface: upstream_iface,
            default_route_ip: default_route_ip,
            namespace_ip: namespace_ip,
        }
    }

    fn create_bridge(&self) -> Result<()> {
        let status = Command::new("brctl")
            .args(&["addbr", &self.bridge_name])
            .status();
        // Allowed to fail if the bridge already exists.
        if status.is_ok() {
            Command::new("brctl").args(&["addif", &self.bridge_name, &self.upstream_iface])
                .status()
                .map_err(Error::AddingInterfaceToBridge)?;
        }
        Ok(())
    }
}

impl NetNamespace for BridgedNetNamespace {
    fn configure_for_pid(&self, pid: pid_t) -> Result<()> {
        // If it doesn't exist, create the bridge and add the upstream interface
        self.create_bridge()?;

        // Create a veth pair and add one end to the specified bridge.

        // TODO(dgreid) - don't hard-code vethC0, select next available number
        // to enable multiple containers
        Command::new("ip")
            .args(&["link", "add", "vethC0Host", "type", "veth", "peer", "name", "vethC0"])
            .status()
            .map_err(Error::AddingVethInterfaces)?;
        Command::new("ip").args(&["link", "set", "vethC0Host", "up"])
            .status()
            .map_err(Error::EnablingHostVeth)?;
        Command::new("brctl").args(&["addif", &self.bridge_name, "vethC0Host"])
            .status()
            .map_err(Error::AddingInterfaceToBridge)?;
        Command::new("ip").args(&["link", "set", &self.bridge_name, "up"])
            .status()
            .map_err(Error::EnablingBridgeInterface)?;
        Command::new("ip").args(&["link", "set", "vethC0Host", "up"])
            .status()
            .map_err(Error::EnablingHostVeth)?;
        Command::new("ip").args(&["link", "set", "vethC0", "netns", &pid.to_string()])
            .status()
            .map_err(Error::SettingNetNamespace)?;
        Command::new("ip").args(&["link", "set", &self.upstream_iface, "up"])
            .status()
            .map_err(Error::EnablingContainerVeth)?;
        Ok(())
    }

    fn configure_in_child(&self) -> Result<()> {
        Command::new("ip").args(&["addr", "add", &self.namespace_ip, "dev", "vethC0"])
            .status()
            .map_err(Error::SettingInterfaceAddress)?;
        Command::new("ip").args(&["link", "set", "vethC0", "up"])
            .status()
            .map_err(Error::EnablingContainerVeth)?;
        Command::new("ip").args(&["route", "add", "default", "via", &self.default_route_ip])
            .status()
            .map_err(Error::SettingDefaultRoute)?;
        enable_device("lo").map_err(Error::EnablingLoopback)?;
        Ok(())
    }
}

pub struct EmptyNetNamespace {}

impl EmptyNetNamespace {
    pub fn new() -> Self {
        EmptyNetNamespace {}
    }
}

impl NetNamespace for EmptyNetNamespace {
    fn configure_for_pid(&self, _: pid_t) -> Result<()> {
        // Only loopback to bring up, that is handled in the child.
        Ok(())
    }

    fn configure_in_child(&self) -> Result<()> {
        // Only loopback to bring up.
        enable_device("lo").map_err(Error::EnablingLoopback)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test1() {}
}
