extern crate container;
extern crate container_config;
extern crate getopts;
extern crate libc;

use container::net_namespace::{NetNamespace, BridgedNetNamespace, EmptyNetNamespace,
                               NatNetNamespace};
use container::user_namespace::UserNamespace;
use container_config::container_config_from_oci_config_file;

use std::env;
use std::path::PathBuf;

struct CommandOptions {
    alt_syscall_table: Option<String>,
    cgroup_parent: Option<String>,
    cgroup_name: Option<String>,
    container_path: Option<PathBuf>,
    extra_argv: Vec<String>,
    net_ns: Option<Box<NetNamespace>>,
    bind_mounts: Option<Vec<(String, String)>>,
    securebits_unlock_mask: Option<usize>,
    use_configured_users: bool,
}

// Examples:
//
//  For a NAT'd network:
//  # run_oci -u -n masquerade --masquerade_dev eth0 --masquerade_dev wlan0 --masquerade_ip 10.1.1.1 --container_ip 10.1.1.2 /mnt/stateful_partition/containers/run_container/
//  For a bridged network:
//  # run_oci -n bridge --container_ip 10.1.1.2/24 --bridge_device veth1 --bridge_name br0 --masquerade_ip 10.1.1.1 /containers/busybox/

impl CommandOptions {
    fn build_opts() -> getopts::Options {
        let mut opts = getopts::Options::new();
        opts.optopt("B",
                    "securebits_skip_mask",
                    "If Capabilities are used by the container config, this \
                     option allows some securebits to not be set.  By default, \
                     SECURE_NOROOT, SECURE_NO_SETUID_FIXUP, and SECURE_KEEP_CAPS \
                     (together with their respective locks) are set.\n",
                     "<unlock bitmask>");
        opts.optmulti("b",
                      "bind_mount",
                      "Add a bind mount from external to internal",
                      "<external dir>:<internal dir>");
        opts.optopt("c", "cgroup_name", "Name to give the cgroup", "NAME");
        opts.optopt("d",
                    "bridge_device",
                    "If network is bridged, the upstream dev to use",
                    "DEV");
        opts.optopt("i",
                    "container_ip",
                    "If network is bridged or NAT, the IP address for the container",
                    "IP");
        opts.optopt("m",
                    "masquerade_ip",
                    "The IP address of the upstream masquerade device",
                    "IP");
        opts.optopt("n",
                    "net_type",
                    "Network Type (bridge, masquerade, or empty)",
                    "TYPE");
        opts.optopt("p",
                    "cgroup_parent",
                    "parent directory of the container cgroups",
                    "NAME");
        opts.optmulti("q",
                      "masquerade_dev",
                      "Upstream device for NAT, can be specified multiple times",
                      "DEV");
        opts.optopt("r",
                    "bridge_name",
                    "If network is bridged, the bridge to use",
                    "NAME");
        opts.optopt("s",
                    "alt_syscall",
                    "Use the given alt-syscall table",
                    "TABLE_NAME");
        opts.optflag("u", "use_current_user", "Map the current user/group only");

        opts
    }

    pub fn new(argv: &Vec<String>) -> Result<CommandOptions, ()> {
        let opts = CommandOptions::build_opts();

        let mut matches = opts.parse(&argv[1..])
            .map_err(|_| {
                CommandOptions::print_usage(&argv[0], &opts);
                ()
            })?;

        if matches.free.len() == 0 {
            CommandOptions::print_usage(&argv[0], &opts);
            return Err(());
        }

        let bind_mounts = CommandOptions::bind_mounts_from_opts(&matches).map_err(|_| {
                CommandOptions::print_usage(&argv[0], &opts);
                ()
            })?;

        let net_ns = CommandOptions::net_ns_from_opts(&matches).map_err(|_| {
                CommandOptions::print_usage(&argv[0], &opts);
                ()
            })?;

        let securebits_unlock_mask = matches.opt_str("B")
                .map(|mask| usize::from_str_radix(&mask, 16).expect("Invalid securebits mask"));

        Ok(CommandOptions {
            alt_syscall_table: matches.opt_str("s"),
            cgroup_parent: matches.opt_str("p"),
            cgroup_name: matches.opt_str("c"),
            container_path: Some(PathBuf::from(&matches.free[0])),
            extra_argv: matches.free.split_off(1),
            net_ns: Some(net_ns),
            bind_mounts: Some(bind_mounts),
            securebits_unlock_mask: securebits_unlock_mask,
            use_configured_users: !matches.opt_present("u"),
        })
    }

    fn bind_mounts_from_opts(matches: &getopts::Matches) -> Result<Vec<(String, String)>, ()> {
        let mut bind_mounts = Vec::new();
        for mount in matches.opt_strs("b").into_iter() {
            let dirs: Vec<&str> = mount.split(":").collect();
            if dirs.len() != 2 {
                println!("Invalid bind mount specified: {}", mount);
                return Err(());
            }
            bind_mounts.push((dirs[0].to_string(), dirs[1].to_string()));
        }
        Ok(bind_mounts)
    }

    fn net_ns_from_opts(matches: &getopts::Matches) -> Result<Box<NetNamespace>, ()> {
        let bridge_name = matches.opt_str("r");
        let bridge_device = matches.opt_str("d");
        let container_ip = matches.opt_str("i");
        let masquerade_ip = matches.opt_str("m");
        let mut masquerade_devices = Vec::new();
        for dev in matches.opt_strs("q").into_iter() {
            masquerade_devices.push(dev);
        }

        matches.opt_str("n").map_or(Ok(Box::new(EmptyNetNamespace::new())), |n| {
            match n.as_ref() {
                "empty" => Ok(Box::new(EmptyNetNamespace::new())),
                "bridge" => {
                    if bridge_name.is_none() || bridge_device.is_none() {
                        println!("bridge_name and bride_device are required");
                        return Err(());
                    }
                    if container_ip.is_none() || masquerade_ip.is_none() {
                        println!("bridge_ip, and masquerate_ip are required");
                        return Err(());
                    }
                    Ok(Box::new(BridgedNetNamespace::new(bridge_name.unwrap(),
                                                         bridge_device.unwrap(),
                                                         masquerade_ip.unwrap(),
                                                         container_ip.unwrap())))
                }
                "masquerade" => {
                    if masquerade_devices.is_empty() || masquerade_ip.is_none() {
                        println!("A device and IP are required for masquerade networking");
                        return Err(());
                    }
                    Ok(Box::new(NatNetNamespace::new(masquerade_devices,
                                                     masquerade_ip.unwrap(),
                                                     container_ip)))
                }
                _ => {
                    println!("Invalid network type");
                    return Err(());
                }
            }
        })
    }

    fn print_usage(program: &str, opts: &getopts::Options) {
        let brief = format!("Usage: {} [options] <Container dir>", program);
        print!("{}", opts.usage(&brief));
    }

    pub fn get_net_namespace(&mut self) -> Box<NetNamespace> {
        self.net_ns.take().unwrap()
    }

    pub fn get_container_path(&mut self) -> PathBuf {
        self.container_path.take().unwrap()
    }

    pub fn should_use_user_config(&self) -> bool {
        self.use_configured_users
    }

    pub fn get_bind_mounts(&mut self) -> Vec<(String, String)> {
        self.bind_mounts.take().unwrap()
    }

    pub fn get_extra_args(&self) -> &Vec<String> {
        &self.extra_argv
    }

    pub fn securebits_unlock_mask(&self) -> Option<usize> {
        self.securebits_unlock_mask
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut cmd_opts = match CommandOptions::new(&argv) {
        Ok(c) => c,
        Err(()) => return,
    };

    let mut cc = container_config_from_oci_config_file(&cmd_opts.get_container_path(),
                                                       cmd_opts.get_bind_mounts(),
                                                       cmd_opts.securebits_unlock_mask())
        .expect("Failed to parse config");

    if let Some(cgroup_parent) = cmd_opts.cgroup_parent.take() {
        cc = cc.cgroup_parent(cgroup_parent);
    }

    if let Some(cgroup_name) = cmd_opts.cgroup_name.take() {
        cc = cc.cgroup_name(cgroup_name);
    }

    cc = cc.net_namespace(Some(cmd_opts.get_net_namespace()));
    if !cmd_opts.should_use_user_config() {
        let mut user_ns = UserNamespace::new();
        user_ns.add_uid_mapping(0, unsafe { libc::getuid() } as u64, 1);
        user_ns.add_gid_mapping(0, unsafe { libc::getgid() } as u64, 1);
        cc = cc.user_namespace(Some(user_ns));
    }
    cc = cc.append_args(cmd_opts.get_extra_args());
    if let Some(t) = cmd_opts.alt_syscall_table {
        cc = cc.alt_syscall_table(Some(&t));
    }

    let mut c = cc.start().unwrap();
    c.wait().unwrap();
}
