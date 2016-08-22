extern crate serde;
extern crate serde_json;

#[derive(Serialize, Deserialize)]
pub struct OciPlatform {
    os: String,
    arch: String,
}

#[derive(Serialize, Deserialize)]
pub struct OciProcessUser {
    uid: u32,
    gid: u32,
    #[serde(rename="additionalGids")]
    additional_gids: Option<Vec<u32>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciRlimit {
    #[serde(rename="type")]
    limit_type: String,
    hard: u32,
    soft: u32,
}

#[derive(Serialize, Deserialize)]
pub struct OciProcess {
    terminal: Option<bool>,
    user: OciProcessUser,
    args: Vec<String>,
    env: Option<Vec<String>>,
    cwd: String,
    capabilities: Option<Vec<String>>,
    rlimits: Option<Vec<OciRlimit>>,
    #[serde(rename="apparmorProfile")]
    apparmor_profile: Option<bool>,
    #[serde(rename="selinuxLabel")]
    selinux_label: Option<bool>,
    #[serde(rename="noNewPrivileges")]
    no_new_privileges: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct OciRoot {
    path: String,
    #[serde(rename="readonly")]
    read_only: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct OciMount {
    destination: String,
    #[serde(rename="type")]
    mount_type: String,
    source: String,
    options: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciHook {
    path: String,
    args: Option<Vec<String>>,
    env: Option<Vec<String>>,
    timeout: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct OciHooks {
    prestart: Option<Vec<OciHook>>,
    poststart: Option<Vec<OciHook>>,
    poststop: Option<Vec<OciHook>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupDevice {
    allow: bool,
    access: Option<String>,
    #[serde(rename="type")]
    dev_type: Option<String>,
    major: Option<u32>,
    minor: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupMemory {
    limit: Option<u64>,
    reservation: Option<u64>,
    swap: Option<u64>,
    kernel: Option<u64>,
    #[serde(rename="kernelTCP")]
    kernel_tcp: Option<u64>,
    swappiness: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupCpu {
    shares: Option<u64>,
    quota: Option<u64>,
    period: Option<u64>,
    #[serde(rename="realtimeRuntime")]
    realtime_runtime: Option<u64>,
    #[serde(rename="realtimePeriod")]
    realtime_period: Option<u64>,
    cpus: Option<String>,
    mems: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupHugePageLimit {
    #[serde(rename="pageSize")]
    page_size: String,
    limit: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupBlockIOWeightDevice {
    major: u64,
    minor: u64,
    weight: Option<u16>,
    #[serde(rename="leafWeight")]
    leaf_weight: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupBlockIOBpsLimit {
    major: u64,
    minor: u64,
    rate: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupBlockIO {
    #[serde(rename="blkioWeight")]
    blkio_weight: Option<u16>,
    #[serde(rename="blkioLeafWeight")]
    blkio_leaf_weight: Option<u16>,
    #[serde(rename="blkioWeightDevice")]
    blkio_weight_device: Option<Vec<OciLinuxCgroupBlockIOWeightDevice>>,
    #[serde(rename="blkioThrottleReadBpsDevice")]
    blkio_throttle_read_bps_device: Option<Vec<OciLinuxCgroupBlockIOBpsLimit>>,
    #[serde(rename="blkioThrottleWriteBpsDevice")]
    blkio_throttle_write_bps_device: Option<Vec<OciLinuxCgroupBlockIO>>,
    #[serde(rename="blkioThrottleReadIOPSDevice")]
    blkio_throttle_read_iops_device: Option<Vec<OciLinuxCgroupBlockIOBpsLimit>>,
    #[serde(rename="blkioThrottleWriteIOPSDevice")]
    blkio_throttle_write_iops_device: Option<Vec<OciLinuxCgroupBlockIO>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupNetworkPriority {
    name: String,
    priority: u32,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupNetwork {
    #[serde(rename="classID")]
    class_id: Option<u32>,
    priorities: Option<Vec<OciLinuxCgroupNetworkPriority>>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxCgroupPids {
    limit: i64,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxResources {
    devices: Option<Vec<OciLinuxCgroupDevice>>,
    #[serde(rename="disableOOMKiller")]
    disable_oom_killer: Option<bool>,
    #[serde(rename="oomScoreAdj")]
    oom_score_adj: Option<i32>,
    memory: Option<OciLinuxCgroupMemory>,
    cpu: Option<OciLinuxCgroupCpu>,
    #[serde(rename="blockIO")]
    block_io: Option<OciLinuxCgroupBlockIO>,
    network: Option<OciLinuxCgroupNetwork>,
    pids: Option<OciLinuxCgroupPids>,
    #[serde(rename="hugePageLimits")]
    huge_page_limits: Option<OciLinuxCgroupHugePageLimit>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxNamespace {
    #[serde(rename="type")]
    namespace_type: String,
    path: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxNamespaceMapping {
    #[serde(rename="hostID")]
    host_id: u64,
    #[serde(rename="containerID")]
    container_id: u64,
    size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinuxDevice {
    #[serde(rename="type")]
    dev_type: String,
    path: String,
    major: Option<u32>,
    minor: Option<u32>,
    #[serde(rename="fileMode")]
    file_mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct OciLinux {
    devices: Option<Vec<OciLinuxDevice>>,
    #[serde(rename="cgroupsPath")]
    cgroups_path: Option<String>,
    resources: Option<OciLinuxResources>,
    namespaces: Option<Vec<OciLinuxNamespace>>,
    #[serde(rename="uidMappings")]
    uid_mappings: Option<Vec<OciLinuxNamespaceMapping>>,
    #[serde(rename="gidMappings")]
    gid_mappings: Option<Vec<OciLinuxNamespaceMapping>>,
    #[serde(rename="maskedPaths")]
    masked_paths: Option<Vec<String>>,
    #[serde(rename="readonlyPaths")]
    read_only_paths: Option<Vec<String>>,
    #[serde(rename="rootfsPropagation")]
    rootfs_propagation: Option<String>,
    #[serde(rename="mountLabel")]
    mount_label: Option<String>,
    // TODO seccomp, sysctl
}

#[derive(Serialize, Deserialize)]
pub struct OciConfig {
    #[serde(rename="ociVersion")]
    oci_version: String,
    platform: OciPlatform,
    root: OciRoot,
    process: OciProcess,
    hostname: Option<String>,
    mounts: Option<Vec<OciMount>>,
    hooks: Option<OciHooks>,
    linux: Option<OciLinux>,
}

#[cfg(test)]
mod tests {
    extern crate serde;
    extern crate serde_json;

    use super::OciLinuxDevice;
    use super::OciLinuxNamespaceMapping;
    use super::OciConfig;

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
                            "type": "pid"
                        },
                        {
                            "type": "network"
                        },
                        {
                            "type": "ipc"
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
                    ]
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
        assert_eq!(basic_config.process.env.as_ref()
            .and_then(|e| e.get(1)), Some(&"TERM=xterm".to_string()));
        assert_eq!(basic_config.process.cwd, "/");
        assert_eq!(basic_config.process.capabilities.as_ref()
            .and_then(|caps| caps.get(2)), Some(&"CAP_NET_BIND_SERVICE".to_string()));
        assert_eq!(basic_config.process.rlimits
            .map(|rlimits| rlimits[0].hard), Some(1024));
        assert_eq!(basic_config.process.apparmor_profile, None);
        assert_eq!(basic_config.process.selinux_label, None);
        assert_eq!(basic_config.process.no_new_privileges, Some(true));
        assert_eq!(basic_config.hostname, Some("tester".to_string()));
        assert_eq!(basic_config.mounts.as_ref().unwrap().get(0).unwrap().options, None);
        assert_eq!(basic_config.mounts.as_ref().unwrap().get(1).unwrap().destination,
                   "/dev".to_string());
        assert_eq!(basic_config.mounts.as_ref().unwrap().get(2).unwrap().options
                .as_ref().unwrap().len(), 6);
        assert_eq!(basic_config.hooks.as_ref().unwrap().prestart.as_ref().unwrap()
                .get(1).unwrap().path, "/usr/bin/setup-network".to_string());
        assert_eq!(basic_config.linux.as_ref().unwrap()
                .resources.as_ref().unwrap()
                .network.as_ref().unwrap().class_id, Some(1048577));
        assert_eq!(basic_config.linux.as_ref().unwrap()
                .masked_paths.as_ref().unwrap().len(), 5);
        assert_eq!(basic_config.linux.as_ref().unwrap()
                .read_only_paths.as_ref().unwrap().len(), 6);
        // Devices
        let dev: &OciLinuxDevice = basic_config.linux.as_ref().unwrap()
                .devices.as_ref().unwrap().get(0).unwrap();
        assert_eq!(dev.dev_type, "c");
        assert_eq!(dev.path, "/dev/fuse");
        assert_eq!(dev.file_mode, Some(438));
        assert_eq!(dev.uid, Some(0));
        // Namespace Maps
        let id_map: &OciLinuxNamespaceMapping = basic_config.linux.as_ref().unwrap()
                .uid_mappings.as_ref().unwrap().get(0).unwrap();
        assert_eq!(id_map.host_id, 1000);
        assert_eq!(id_map.container_id, 0);
        assert_eq!(id_map.size, 10);
    }
}
