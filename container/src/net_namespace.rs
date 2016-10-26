extern crate nix;

use self::nix::sys::ioctl::libc::pid_t;
use std::io;
use std::process::Command;

// Parent side configuration for a network namespace

pub enum Error {
    Io(io::Error),
    NetNamespaceDeviceSetupFailed,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

fn enable_device(dev: &str) -> Result<(), Error> {
    try!(Command::new("ip")
            .args(&["link", "set", dev, "up"])
            .status());
    Ok(())
}

pub trait NetNamespace {
    fn configure_for_pid(&self, pid: pid_t) -> Result<(), Error>;
    fn configure_in_child(&self) -> Result<(), Error>;
}

pub struct NatNetNamespace {
    upstream_ifaces: Vec<String>,
    ip_addr: String, // ip address of the host-side interface for NAT
}

impl NatNetNamespace {
    pub fn new(upstream_ifaces: Vec<String>, ip_addr: String) -> Self {
        NatNetNamespace { upstream_ifaces: upstream_ifaces, ip_addr: ip_addr }
    }
}

impl NetNamespace for NatNetNamespace {
    fn configure_for_pid(&self, pid: pid_t) -> Result<(), Error> {
        // Crate a veth pair, set up masquerade for one port, give the other to
        // the pid's net namespace.
        // TODO - don't hard-code veth0,veth1
        try!(Command::new("ip")
                     .args(&["link", "add", "veth0", "type", "veth", "peer", "name", "veth1"])
                     .status());
        try!(Command::new("ip")
                     .args(&["addr", "add", &self.ip_addr, "dev", "veth0"])
                     .status());
        try!(Command::new("ip")
                     .args(&["link", "set", "veth0", "up"])
                     .status());
        try!(Command::new("ip")
                     .args(&["link", "set", "veth1", "up"])
                     .status());
        try!(Command::new("ip")
                     .args(&["link", "set", "veth1", "netns", &pid.to_string()])
                     .status());
        // iptables nat masquerade setup
        for iface in self.upstream_ifaces.iter() {
            try!(Command::new("iptables")
                         .args(&["-t", "nat", "-A", "POSTROUTING", "-o", &iface,
                                 "-j", "MASQUERADE"])
                         .status());
            try!(Command::new("iptables")
                         .args(&["-A", "FORWARD", "-i", "veth0", "-o", &iface,
                             "-m", "state", "--state", "RELATED,ESTABLISHED",
                             "-j", "ACCEPT"])
                         .status());
            try!(Command::new("iptables")
                         .args(&["-A", "FORWARD", "-i", "veth0", "-o", &iface,
                             "-j", "ACCEPT"])
                         .status());
        }
        try!(Command::new("sysctl")
                      .arg("net.ipv4.ip_forward=1")
                      .status());

        Ok(())
    }

    fn configure_in_child(&self) -> Result<(), Error> {
        try!(enable_device("lo"));
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
    pub fn new(bridge_name: String, upstream_iface: String, default_route_ip: String,
               namespace_ip: String) -> Self {
        BridgedNetNamespace { bridge_name: bridge_name,
                              upstream_iface: upstream_iface,
                              default_route_ip: default_route_ip,
                              namespace_ip: namespace_ip,
                            }
    }

    fn create_bridge(&self) -> Result<(), Error> {
        let status = Command::new("brctl")
                              .args(&["addbr", &self.bridge_name])
                              .status();
        // Allowed to fail if the bridge already exists.
        if status.is_ok() {
            try!(Command::new("brctl")
                          .args(&["addif", &self.bridge_name, &self.upstream_iface])
                          .status());
        }
        Ok(())
    }
}

impl NetNamespace for BridgedNetNamespace {
    fn configure_for_pid(&self, pid: pid_t) -> Result<(), Error> {
        // If it doesn't exist, create the bridge and add the upstream interface
        try!(self.create_bridge());

        // Create a veth pair and add one end to the specified bridge.

        // TODO(dgreid) - don't hard-code vethC0, select next available number
        // to enable multiple containers
        try!(Command::new("ip")
                     .args(&["link", "add", "vethC0Host", "type", "veth", "peer", "name", "vethC0"])
                     .status());
        try!(Command::new("ip")
                      .args(&["link", "set", "vethC0Host", "up"])
                      .status());
        try!(Command::new("brctl")
                      .args(&["addif", &self.bridge_name, "vethC0Host"])
                      .status());
        try!(Command::new("ip")
                      .args(&["link", "set", &self.bridge_name, "up"])
                      .status());
        try!(Command::new("ip")
                      .args(&["link", "set", "vethC0Host", "up"])
                      .status());
        try!(Command::new("ip")
                     .args(&["link", "set", "vethC0", "netns", &pid.to_string()])
                     .status());
        try!(Command::new("ip")
                      .args(&["link", "set", &self.upstream_iface, "up"])
                      .status());
        Ok(())
    }

    fn configure_in_child(&self) -> Result<(), Error> {
        try!(Command::new("ip")
                      .args(&["addr", "add", &self.namespace_ip, "dev", "vethC0"])
                      .status());
        try!(Command::new("ip")
                      .args(&["link", "set", "vethC0", "up"])
                      .status());
        try!(Command::new("ip")
                      .args(&["route", "add", "default", "via", &self.default_route_ip])
                      .status());
        try!(enable_device("lo"));
        Ok(())
    }
}

pub struct EmptyNetNamespace {
}

impl EmptyNetNamespace {
    pub fn new() -> Self {
        EmptyNetNamespace { }
    }
}

impl NetNamespace for EmptyNetNamespace {
    fn configure_for_pid(&self, _: pid_t) -> Result<(), Error> {
        // Only loopback to bring up, that is handled in the child.
        Ok(())
    }

    fn configure_in_child(&self) -> Result<(), Error> {
        // Only loopback to bring up.
        try!(enable_device("lo"));
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test1() {
    }
}
