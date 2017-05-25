extern crate serde;
extern crate serde_json;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct OciPlatform {
    pub os: String,
    pub arch: String,
}

#[derive(Serialize, Deserialize)]
pub struct OciProcessUser {
    pub uid: u32,
    pub gid: u32,
    #[serde(rename="additionalGids")]
    pub additional_gids: Option<Vec<u32>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciRlimit {
    #[serde(rename="type")]
    pub limit_type: String,
    pub hard: u32,
    pub soft: u32,
}

#[derive(Serialize, Deserialize)]
pub struct OciProcess {
    pub terminal: Option<bool>,
    pub user: OciProcessUser,
    pub args: Vec<String>,
    pub env: Option<Vec<String>>,
    pub cwd: String,
    pub capabilities: Option<Vec<String>>,
    pub rlimits: Option<Vec<OciRlimit>>,
    #[serde(rename="apparmorProfile")]
    pub apparmor_profile: Option<bool>,
    #[serde(rename="selinuxLabel")]
    pub selinux_label: Option<bool>,
    #[serde(rename="noNewPrivileges")]
    pub no_new_privileges: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct OciRoot {
    pub path: String,
    #[serde(rename="readonly")]
    pub read_only: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    #[serde(rename="type")]
    pub mount_type: String,
    pub source: String,
    pub options: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciHook {
    pub path: String,
    pub args: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub timeout: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct OciHooks {
    pub prestart: Option<Vec<OciHook>>,
    pub poststart: Option<Vec<OciHook>>,
    pub poststop: Option<Vec<OciHook>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupDevice {
    pub allow: bool,
    pub access: Option<String>,
    #[serde(rename="type")]
    pub dev_type: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupMemory {
    pub limit: Option<u64>,
    pub reservation: Option<u64>,
    pub swap: Option<u64>,
    pub kernel: Option<u64>,
    #[serde(rename="kernelTCP")]
    pub kernel_tcp: Option<u64>,
    pub swappiness: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupCpu {
    pub shares: Option<u64>,
    pub quota: Option<u64>,
    pub period: Option<u64>,
    #[serde(rename="realtimeRuntime")]
    pub realtime_runtime: Option<u64>,
    #[serde(rename="realtimePeriod")]
    pub realtime_period: Option<u64>,
    pub cpus: Option<String>,
    pub mems: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupHugePageLimit {
    #[serde(rename="pageSize")]
    pub page_size: String,
    pub limit: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupBlockIOWeightDevice {
    pub major: u64,
    pub minor: u64,
    pub weight: Option<u16>,
    #[serde(rename="leafWeight")]
    pub leaf_weight: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupBlockIOBpsLimit {
    pub major: u64,
    pub minor: u64,
    pub rate: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupBlockIO {
    #[serde(rename="blkioWeight")]
    pub blkio_weight: Option<u16>,
    #[serde(rename="blkioLeafWeight")]
    pub blkio_leaf_weight: Option<u16>,
    #[serde(rename="blkioWeightDevice")]
    pub blkio_weight_device: Option<Vec<OciLinuxCgroupBlockIOWeightDevice>>,
    #[serde(rename="blkioThrottleReadBpsDevice")]
    pub blkio_throttle_read_bps_device: Option<Vec<OciLinuxCgroupBlockIOBpsLimit>>,
    #[serde(rename="blkioThrottleWriteBpsDevice")]
    pub blkio_throttle_write_bps_device: Option<Vec<OciLinuxCgroupBlockIO>>,
    #[serde(rename="blkioThrottleReadIOPSDevice")]
    pub blkio_throttle_read_iops_device: Option<Vec<OciLinuxCgroupBlockIOBpsLimit>>,
    #[serde(rename="blkioThrottleWriteIOPSDevice")]
    pub blkio_throttle_write_iops_device: Option<Vec<OciLinuxCgroupBlockIO>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupNetworkPriority {
    pub name: String,
    pub priority: u32,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupNetwork {
    #[serde(rename="classID")]
    pub class_id: Option<u32>,
    pub priorities: Option<Vec<OciLinuxCgroupNetworkPriority>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupPids {
    pub limit: i64,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxResources {
    pub devices: Option<Vec<OciLinuxCgroupDevice>>,
    #[serde(rename="disableOOMKiller")]
    pub disable_oom_killer: Option<bool>,
    #[serde(rename="oomScoreAdj")]
    pub oom_score_adj: Option<i32>,
    pub memory: Option<OciLinuxCgroupMemory>,
    pub cpu: Option<OciLinuxCgroupCpu>,
    #[serde(rename="blockIO")]
    pub block_io: Option<OciLinuxCgroupBlockIO>,
    pub network: Option<OciLinuxCgroupNetwork>,
    pub pids: Option<OciLinuxCgroupPids>,
    #[serde(rename="hugePageLimits")]
    pub huge_page_limits: Option<OciLinuxCgroupHugePageLimit>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxNamespace {
    #[serde(rename="type")]
    pub namespace_type: String,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxNamespaceMapping {
    #[serde(rename="hostID")]
    pub host_id: u64,
    #[serde(rename="containerID")]
    pub container_id: u64,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxDevice {
    #[serde(rename="type")]
    pub dev_type: String,
    pub path: String,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    #[serde(rename="fileMode")]
    pub file_mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct OciSeccompArg {
    pub index: u32,
    pub value: u64,
    pub value2: u64,
    pub op: String,
}

#[derive(Serialize, Deserialize)]
pub struct OciSeccompSyscall {
    pub name: String,
    pub action: String,
    pub args: Option<Vec<OciSeccompArg>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciSeccomp {
    #[serde(rename="defaultAction")]
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<OciSeccompSyscall>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinux {
    pub devices: Option<Vec<OciLinuxDevice>>,
    #[serde(rename="cgroupsPath")]
    pub cgroups_path: Option<String>,
    pub resources: Option<OciLinuxResources>,
    pub namespaces: Option<Vec<OciLinuxNamespace>>,
    #[serde(rename="uidMappings")]
    pub uid_mappings: Option<Vec<OciLinuxNamespaceMapping>>,
    #[serde(rename="gidMappings")]
    pub gid_mappings: Option<Vec<OciLinuxNamespaceMapping>>,
    #[serde(rename="maskedPaths")]
    pub masked_paths: Option<Vec<String>>,
    #[serde(rename="readonlyPaths")]
    pub read_only_paths: Option<Vec<String>>,
    #[serde(rename="rootfsPropagation")]
    pub rootfs_propagation: Option<String>,
    #[serde(rename="mountLabel")]
    pub mount_label: Option<String>,
    pub seccomp: Option<OciSeccomp>,
    pub sysctl: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciConfig {
    #[serde(rename="ociVersion")]
    pub oci_version: String,
    pub platform: OciPlatform,
    pub root: OciRoot,
    pub process: OciProcess,
    pub hostname: Option<String>,
    pub mounts: Option<Vec<OciMount>>,
    pub hooks: Option<OciHooks>,
    pub linux: Option<OciLinux>, // TODO - Annotations
}

#[cfg(test)]
mod tests {
    extern crate serde;
    extern crate serde_json;

    use std::collections::HashMap;

    use super::OciLinuxDevice;
    use super::OciLinuxNamespace;
    use super::OciLinuxNamespaceMapping;
    use super::OciConfig;
    use super::OciSeccomp;

    #[test]
    fn json_test() {
        let basic_json_str = r#"
            {
                "ociVersion": "1.0.0-rc1",
                "platform": {
                    "os": "linux",
                    "arch": "amd64"
                },
                "root": {
                    "path": "rootfs",
                    "readonly": true
                },
                "process": {
		    "terminal": true,
                    "user": {
                        "uid": 0,
                        "gid": 0
                    },
                    "args": [
                        "sh"
                    ],
                    "env": [
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "TERM=xterm"
                    ],
                    "cwd": "/",
                    "capabilities": [
                        "CAP_AUDIT_WRITE",
                        "CAP_KILL",
                        "CAP_NET_BIND_SERVICE"
                    ],
                    "rlimits": [
                        {
                            "type": "RLIMIT_NOFILE",
                            "hard": 1024,
                            "soft": 1024
                        }
                    ],
                    "noNewPrivileges": true
                },
                "hostname": "tester",
                "mounts": [
                    {
                        "destination": "/proc",
                        "type": "proc",
                        "source": "proc"
                    },
                    {
                        "destination": "/dev",
                        "type": "tmpfs",
                        "source": "tmpfs",
                        "options": [
                                "nosuid",
                                "strictatime",
                                "mode=755",
                                "size=65536k"
                        ]
                    },
                    {
                        "destination": "/dev/pts",
                        "type": "devpts",
                        "source": "devpts",
                        "options": [
                                "nosuid",
                                "noexec",
                                "newinstance",
                                "ptmxmode=0666",
                                "mode=0620",
                                "gid=5"
                        ]
                    },
                    {
                        "destination": "/dev/shm",
                        "type": "tmpfs",
                        "source": "shm",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "mode=1777",
                                "size=65536k"
                        ]
                    },
                    {
                        "destination": "/dev/mqueue",
                        "type": "mqueue",
                        "source": "mqueue",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev"
                        ]
                    },
                    {
                        "destination": "/sys",
                        "type": "sysfs",
                        "source": "sysfs",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "ro"
                        ]
                    },
                    {
                        "destination": "/sys/fs/cgroup",
                        "type": "cgroup",
                        "source": "cgroup",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "relatime",
                                "ro"
                        ]
                    }
                ],
                "hooks" : {
                    "prestart": [
                        {
                            "path": "/usr/bin/fix-mounts",
                            "args": ["fix-mounts", "arg1", "arg2"],
                            "env":  [ "key1=value1"]
                        },
                        {
                            "path": "/usr/bin/setup-network"
                        }
                    ],
                    "poststart": [
                        {
                            "path": "/usr/bin/notify-start",
                            "timeout": 5
                        }
                    ],
                    "poststop": [
                        {
                            "path": "/usr/sbin/cleanup.sh",
                            "args": ["cleanup.sh", "-f"]
                        }
                    ]
                },
                "linux": {
                    "devices": [
                        {
                            "path": "/dev/fuse",
                            "type": "c",
                            "major": 10,
                            "minor": 229,
                            "fileMode": 438,
                            "uid": 0,
                            "gid": 0
                        },
                        {
                            "path": "/dev/sda",
                            "type": "b",
                            "major": 8,
                            "minor": 0,
                            "fileMode": 432,
                            "uid": 0,
                            "gid": 0
                        }
                    ],
                    "resources": {
                        "devices": [
                            {
                                "allow": false,
                                "access": "rwm"
                            },
                            {
                                "allow": true,
                                "type": "c",
                                "major": 10,
                                "minor": 229,
                                "access": "rw"
                            }
                        ],
                        "network": {
                            "classID": 1048577,
                            "priorities": [
                                {
                                    "name": "eth0",
                                    "priority": 500
                                },
                                {
                                    "name": "eth1",
                                    "priority": 1000
                                }
                            ]
                        }
                    },
                    "namespaces": [
                        {
                            "type": "cgroup"
                        },
                        {
                            "type": "pid"
                        },
                        {
                            "type": "network"
                        },
                        {
                            "type": "ipc"
                        },
                        {
                            "type": "user"
                        },
                        {
                            "type": "uts"
                        },
                        {
                            "type": "mount"
                        }
                    ],
                    "uidMappings": [
                        {
                            "hostID": 1000,
                            "containerID": 0,
                            "size": 10
                        }
                    ],
                    "gidMappings": [
                        {
                            "hostID": 1000,
                            "containerID": 0,
                            "size": 10
                        }
                    ],
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/latency_stats",
                        "/proc/timer_list",
                        "/proc/timer_stats",
                        "/proc/sched_debug"
                    ],
                    "readonlyPaths": [
                        "/proc/asound",
                        "/proc/bus",
                        "/proc/fs",
                        "/proc/irq",
                        "/proc/sys",
                        "/proc/sysrq-trigger"
                    ],
                    "sysctl": {
                        "net.ipv4.ip_forward": "1",
                        "net.core.somaxconn": "256"
                    },
                    "seccomp": {
                        "defaultAction": "SCMP_ACT_KILL",
                        "architectures": [
                            "SCMP_ARCH_X86"
                        ],
                        "syscalls": [
                            {
                                "name": "read",
                                "action": "SCMP_ACT_ALLOW"
                            },
                            {
                                "name": "write",
                                "action": "SCMP_ACT_ALLOW",
                                "args": [
                                    {
                                        "index": 1,
                                        "value": 255,
                                        "value2": 4,
                                        "op": "SCMP_CMP_EQ"
                                    }
                                ]
                            }
                        ]
                    }
		}
            }
        "#;

        let basic_config: OciConfig = serde_json::from_str(basic_json_str).unwrap();
        assert_eq!(basic_config.oci_version, "1.0.0-rc1");
        assert_eq!(basic_config.platform.os, "linux");
        assert_eq!(basic_config.root.path, "rootfs");
        assert_eq!(basic_config.root.read_only, Some(true));
        assert_eq!(basic_config.process.terminal, Some(true));
        assert_eq!(basic_config.process.user.uid, 0);
        assert_eq!(basic_config.process.user.gid, 0);
        assert_eq!(basic_config.process.user.additional_gids, None);
        assert_eq!(basic_config.process.args[0], "sh");
        assert_eq!(basic_config.process
                       .env
                       .as_ref()
                       .and_then(|e| e.get(1)),
                   Some(&"TERM=xterm".to_string()));
        assert_eq!(basic_config.process.cwd, "/");
        assert_eq!(basic_config.process
                       .capabilities
                       .as_ref()
                       .and_then(|caps| caps.get(2)),
                   Some(&"CAP_NET_BIND_SERVICE".to_string()));
        assert_eq!(basic_config.process
                       .rlimits
                       .map(|rlimits| rlimits[0].hard),
                   Some(1024));
        assert_eq!(basic_config.process.apparmor_profile, None);
        assert_eq!(basic_config.process.selinux_label, None);
        assert_eq!(basic_config.process.no_new_privileges, Some(true));
        assert_eq!(basic_config.hostname, Some("tester".to_string()));
        assert_eq!(basic_config.mounts.as_ref().unwrap().get(0).unwrap().options,
                   None);
        assert_eq!(basic_config.mounts.as_ref().unwrap().get(1).unwrap().destination,
                   "/dev".to_string());
        assert_eq!(basic_config.mounts
                       .as_ref()
                       .unwrap()
                       .get(2)
                       .unwrap()
                       .options
                       .as_ref()
                       .unwrap()
                       .len(),
                   6);
        assert_eq!(basic_config.hooks
                       .as_ref()
                       .unwrap()
                       .prestart
                       .as_ref()
                       .unwrap()
                       .get(1)
                       .unwrap()
                       .path,
                   "/usr/bin/setup-network".to_string());
        assert_eq!(basic_config.linux
                       .as_ref()
                       .unwrap()
                       .resources
                       .as_ref()
                       .unwrap()
                       .network
                       .as_ref()
                       .unwrap()
                       .class_id,
                   Some(1048577));
        assert_eq!(basic_config.linux
                       .as_ref()
                       .unwrap()
                       .masked_paths
                       .as_ref()
                       .unwrap()
                       .len(),
                   5);
        assert_eq!(basic_config.linux
                       .as_ref()
                       .unwrap()
                       .read_only_paths
                       .as_ref()
                       .unwrap()
                       .len(),
                   6);
        // Devices
        let dev: &OciLinuxDevice = basic_config.linux
            .as_ref()
            .unwrap()
            .devices
            .as_ref()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(dev.dev_type, "c");
        assert_eq!(dev.path, "/dev/fuse");
        assert_eq!(dev.file_mode, Some(438));
        assert_eq!(dev.uid, Some(0));
        // Namespace Maps
        let id_map: &OciLinuxNamespaceMapping = basic_config.linux
            .as_ref()
            .unwrap()
            .uid_mappings
            .as_ref()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(id_map.host_id, 1000);
        assert_eq!(id_map.container_id, 0);
        assert_eq!(id_map.size, 10);
        // sysctl
        let sysctl: &HashMap<String, String> = basic_config.linux.as_ref().unwrap().sysctl.as_ref().unwrap();
        assert_eq!(sysctl["net.ipv4.ip_forward"], "1");
        // seccomp
        let seccomp: &OciSeccomp = basic_config.linux.as_ref().unwrap().seccomp.as_ref().unwrap();
        assert_eq!(seccomp.default_action, "SCMP_ACT_KILL");
        assert_eq!(seccomp.architectures[0], "SCMP_ARCH_X86");
        assert_eq!(seccomp.syscalls[0].name, "read");
        assert_eq!(seccomp.syscalls[0].action, "SCMP_ACT_ALLOW");
        assert_eq!(seccomp.syscalls[1].name, "write");
        assert_eq!(seccomp.syscalls[1].action, "SCMP_ACT_ALLOW");
        assert_eq!(seccomp.syscalls[1].args.as_ref().unwrap()[0].index, 1);
        assert_eq!(seccomp.syscalls[1].args.as_ref().unwrap()[0].value, 255);
        assert_eq!(seccomp.syscalls[1].args.as_ref().unwrap()[0].value2, 4);
        assert_eq!(seccomp.syscalls[1].args.as_ref().unwrap()[0].op,
                   "SCMP_CMP_EQ");
        // Namespaces
        let namespaces = basic_config.linux.as_ref().unwrap().namespaces.as_ref().unwrap();
        assert_eq!(7,
                   namespaces.iter()
                       .filter(|f| {
                match f.namespace_type.as_ref() {
                    "cgroup" | "ipc" | "network" | "pid" | "uts" | "mount" | "user" => true,
                    _ => false,
                }
            })
                       .collect::<Vec<&OciLinuxNamespace>>()
                       .len());
	// Resources
	let resources = basic_config.linux.as_ref().unwrap().resources.as_ref().unwrap();
	let devices = resources.devices.as_ref().unwrap();
	let all_deny = devices.get(0).unwrap();
	assert!(!all_deny.allow);
	assert_eq!(all_deny.access, Some("rwm".to_string()));
	assert_eq!(all_deny.dev_type, None);
	assert_eq!(all_deny.major, None);
	assert_eq!(all_deny.minor, None);
	let rw_10_229 = devices.get(1).unwrap();
	assert!(rw_10_229.allow);
	assert_eq!(rw_10_229.access, Some("rw".to_string()));
	assert_eq!(rw_10_229.dev_type, Some("c".to_string()));
	assert_eq!(rw_10_229.major, Some(10));
	assert_eq!(rw_10_229.minor, Some(229));
    }
}
