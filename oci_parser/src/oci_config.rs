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
pub struct OciConfig {
    #[serde(rename="ociVersion")]
    oci_version: String,
    platform: OciPlatform,
    root: OciRoot,
    process: OciProcess,
    hostname: Option<String>,
    mounts: Option<Vec<OciMount>>,
}

#[cfg(test)]
mod tests {
    extern crate serde;
    extern crate serde_json;

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
                ]
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
    }
}
