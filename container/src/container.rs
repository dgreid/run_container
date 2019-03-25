extern crate caps;
extern crate libc;

use self::caps::CapConfig;
use cgroup::{self, CGroup};
use cgroup_namespace::{self, CGroupNamespace};
use devices::{self, DeviceConfig};
use hook::{self, Hook, HookState};
use mount_namespace::{self, MountNamespace};
use net_namespace;
use net_namespace::NetNamespace;
use rlimits::{self, RLimits};
use seccomp_jail;
use seccomp_jail::SeccompJail;
use sync_pipe::{self, SyncPipe};
use syscall_defines::linux::LinuxSyscall::*;
use sysctls;
use sysctls::Sysctls;
use user_namespace::{self, UserNamespace};

use self::libc::pid_t;
use libc::sethostname;
use libc::{CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS};
use std;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;

pub struct Container {
    name: String,
    alt_syscall_table: Option<CString>,
    argv: Vec<CString>,
    caps: Option<CapConfig>,
    cgroups: Vec<CGroup>,
    cgroup_namespace: Option<CGroupNamespace>,
    device_config: Option<DeviceConfig>,
    mount_namespace: Option<MountNamespace>,
    user_namespace: Option<UserNamespace>,
    net_namespace: Option<Box<NetNamespace>>,
    no_new_privileges: bool,
    rlimits: Option<RLimits>,
    seccomp_jail: Option<SeccompJail>,
    selinux_label: Option<CString>,
    sysctls: Option<Sysctls>,
    additional_groups: Vec<u32>,
    poststart_hooks: Vec<Hook>,
    poststop_hooks: Vec<Hook>,
    prestart_hooks: Vec<Hook>,
    hook_template: Option<Box<HookState>>,
    privileged: bool,
    pid: pid_t,
}

#[derive(Debug)]
pub enum Error {
    AltSyscallError,
    BoundingCaps(caps::Error),
    CGroupAddPid(cgroup::Error),
    CGroupConfigure(cgroup::Error),
    CGroupCreateError,
    CGroupFailure(cgroup::Error),
    CGroupNamespaceEnter(cgroup_namespace::Error),
    CloneSyscall(i32),
    DroppingCaps(caps::Error),
    GettingThreadID(i32),
    HookFailure(hook::Error),
    InvalidCGroup,
    Io(io::Error),
    MountSetup(mount_namespace::Error),
    NetworkConfigureChild(net_namespace::Error),
    NetworkNamespaceConfigure(net_namespace::Error),
    SetHostName(libc::c_int),
    NoNewPrivsFailed(i32),
    OpenSelinuxAttr(io::Error),
    PreForkDeviceSetup(devices::Error),
    RLimitsError(rlimits::Error),
    SeccompError(seccomp_jail::Error),
    SetGroupsError,
    SettingPGid(i32),
    SettingRootGid(i32),
    SettingRootUid(i32),
    SignalChild(sync_pipe::Error),
    SyncPipeCreation(sync_pipe::Error),
    SysctlError(sysctls::Error),
    UserNamespaceConfigure(user_namespace::Error),
    WaitPidFailed(i32),
    WriteSelinuxLabel(io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

fn get_tid() -> Result<libc::pid_t> {
    unsafe {
        let tid = libc::syscall(SYS_gettid as i64);
        if tid < 0 {
            return Err(Error::GettingThreadID(*libc::__errno_location()));
        }
        Ok(tid as libc::pid_t)
    }
}

fn do_selinux(label: &CString) -> Result<()> {
    let tid = get_tid()?;
    let exec_path = PathBuf::from(format!("/proc/self/task/{}/attr/exec", tid));
    let mut f = File::create(exec_path).map_err(Error::OpenSelinuxAttr)?;
    f.write_all(label.as_bytes())
        .map_err(Error::WriteSelinuxLabel)?;
    Ok(())
}

impl Container {
    pub fn new(
        name: &str,
        argv: Vec<CString>,
        caps: Option<CapConfig>,
        cgroups: Vec<CGroup>,
        cgroup_namespace: Option<CGroupNamespace>,
        device_config: Option<DeviceConfig>,
        mount_namespace: Option<MountNamespace>,
        net_namespace: Option<Box<NetNamespace>>,
        user_namespace: Option<UserNamespace>,
        additional_groups: Vec<u32>,
        no_new_privileges: bool,
        poststart_hooks: Vec<Hook>,
        poststop_hooks: Vec<Hook>,
        prestart_hooks: Vec<Hook>,
        hook_state: Option<Box<HookState>>,
        rlimits: Option<RLimits>,
        seccomp_jail: Option<SeccompJail>,
        selinux_label: Option<CString>,
        sysctls: Option<Sysctls>,
        privileged: bool,
    ) -> Self {
        Container {
            name: name.to_string(),
            alt_syscall_table: None,
            argv: argv,
            caps: caps,
            cgroups: cgroups,
            cgroup_namespace: cgroup_namespace,
            device_config: device_config,
            mount_namespace: mount_namespace,
            net_namespace: net_namespace,
            user_namespace: user_namespace,
            additional_groups: additional_groups,
            no_new_privileges: no_new_privileges,
            rlimits: rlimits,
            seccomp_jail: seccomp_jail,
            selinux_label: selinux_label,
            sysctls: sysctls,
            poststart_hooks: poststart_hooks,
            poststop_hooks: poststop_hooks,
            prestart_hooks: prestart_hooks,
            hook_template: hook_state,
            privileged: privileged,
            pid: 0,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn do_seccomp(&self) -> Result<()> {
        if let Some(ref sj) = self.seccomp_jail {
            sj.enter().map_err(Error::SeccompError)?;
        }
        Ok(())
    }

    fn enter_alt_syscall_table(&self) -> Result<()> {
        if let Some(ref ast) = self.alt_syscall_table {
            unsafe {
                // Calling prctl is safe, it doesn't touch memory.
                if libc::prctl(
                    0x43724f53, // PR_ALT_SYSCALL
                    1,
                    ast.as_ptr(),
                ) != 0
                {
                    return Err(Error::AltSyscallError);
                }
            }
        }
        Ok(())
    }

    fn enter_jail_in_ns(&self) -> Result<()> {
        // Start by setting selinux label - When should selinux be enabled?
        self.selinux_label
            .as_ref()
            .map_or(Ok(()), |l| do_selinux(l))?;

        if self.no_new_privileges {
            unsafe {
                // Calling prctl is safe, it doesn't touch memory.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(Error::NoNewPrivsFailed(*libc::__errno_location()));
                }
            }
        } else {
            // Without NoNewPrivileges seccomp is a privileged operation, so we
            // need to do this before dropping capabilities; otherwise do it
            // last so as few syscalls take place after it as possible.
            self.do_seccomp()?;
        }

        if let Some(ref caps) = self.caps {
            caps.drop_bounding_caps().map_err(Error::BoundingCaps)?;
            caps.drop_caps().map_err(Error::DroppingCaps)?;
        }

        self.enter_alt_syscall_table()?;

        if self.no_new_privileges {
            self.do_seccomp()?;
        }

        Ok(())
    }

    fn set_additional_gids(&self) -> Result<()> {
        if self.additional_groups.is_empty() {
            return Ok(());
        }

        unsafe {
            match libc::setgroups(
                self.additional_groups.len(),
                self.additional_groups.as_ptr(),
            ) {
                0 => Ok(()),
                _ => Err(Error::SetGroupsError),
            }
        }
    }

    fn enter_jail(&self) -> Result<()> {
        unsafe {
            // Setting the uid or gid doesn't touch memory.
            if libc::setresuid(0, 0, 0) < 0 {
                return Err(Error::SettingRootUid(*libc::__errno_location()));
            }
            if libc::setresgid(0, 0, 0) < 0 {
                return Err(Error::SettingRootGid(*libc::__errno_location()));
            }
        }
        self.set_additional_gids()?;
        if let Some(ref net_ns) = self.net_namespace {
            net_ns
                .configure_in_child()
                .map_err(Error::NetworkConfigureChild)?;
        }
        if let Some(ref cg_ns) = self.cgroup_namespace {
            cg_ns.enter().map_err(Error::CGroupNamespaceEnter)?;
        }
        if let Some(ref mnt_ns) = self.mount_namespace {
            mnt_ns
                .enter(|rootpath| {
                    if let Some(ref device_config) = self.device_config {
                        device_config
                            .setup_in_namespace(&rootpath.join("dev"), Some(&PathBuf::from("/dev")))
                            .map_err(|_| ())?;
                    }
                    Ok(())
                })
                .map_err(Error::MountSetup)?;
        }
        if let Some(ref sysctls) = self.sysctls {
            sysctls.configure().map_err(Error::SysctlError)?;
        }

        unsafe {
            match sethostname(self.name.as_ptr() as *const _, self.name.len()) {
                e if e <= 0 => return Err(Error::SetHostName(e)),
                _ => (),
            }
        }
        self.enter_jail_in_ns()?;
        Ok(())
    }

    fn clone_flags(&self) -> libc::c_int {
        let base_flags = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS;
        if self.net_namespace.is_some() {
            base_flags | CLONE_NEWNET
        } else {
            base_flags
        }
    }

    fn do_clone(&self) -> Result<pid_t> {
        unsafe {
            if libc::setpgid(0, 0) < 0 {
                return Err(Error::SettingPGid(*libc::__errno_location()));
            }
        }

        unsafe {
            let pid = libc::syscall(
                libc::SYS_clone as i64,
                self.clone_flags() | libc::SIGCHLD as i32,
                0,
            );
            if pid < 0 {
                Err(Error::CloneSyscall(*libc::__errno_location()))
            } else {
                Ok(pid as pid_t)
            }
        }
    }

    fn parent_setup(
        &mut self,
        ns_ready_signal: SyncPipe,
        ns_setup_complete: SyncPipe,
    ) -> Result<()> {
        self.user_namespace
            .as_ref()
            .map_or(Ok(()), |u| u.configure(self.pid, !self.privileged))
            .map_err(Error::UserNamespaceConfigure)?;
        self.net_namespace
            .as_ref()
            .map_or(Ok(()), |n| n.configure_for_pid(self.pid))
            .map_err(Error::NetworkNamespaceConfigure)?;

        for cgroup in &self.cgroups {
            cgroup.configure().map_err(Error::CGroupConfigure)?;
            cgroup.add_pid(self.pid).map_err(Error::CGroupAddPid)?;
        }

        self.rlimits
            .as_ref()
            .map_or(Ok(()), |r| r.configure(self.pid))
            .map_err(Error::RLimitsError)?;

        ns_ready_signal.signal().map_err(Error::SignalChild)?;
        ns_setup_complete.wait().map_err(Error::SignalChild)?;
        for h in self.prestart_hooks.iter() {
            h.run(
                self.hook_template
                    .as_ref()
                    .map(|t| t.to_string(Some(self.pid as u64), "created")),
            )
            .map_err(Error::HookFailure)?;
        }
        ns_ready_signal.signal().map_err(Error::SignalChild)?;
        Ok(())
    }

    // The client should panic on all failures
    fn run_child(&self, ns_ready_signal: SyncPipe, ns_setup_complete: SyncPipe) {
        ns_ready_signal.wait().unwrap();
        self.enter_jail().unwrap();
        ns_setup_complete.signal().unwrap();
        drop(ns_setup_complete); // Make sure the FD is closed.
        ns_ready_signal.wait().unwrap(); // Wait for post NS setup by the parent.
        drop(ns_ready_signal); // Done with the pipe.
        unsafe {
            libc::execv(
                self.argv[0].as_ptr() as *const _,
                self.argv.as_ptr() as *const _,
            );
        }
        panic!("Failed to execute program");
    }

    pub fn start(&mut self) -> Result<()> {
        let mode = if self.privileged {
            devices::NodeCreateMethod::MakeNode
        } else {
            devices::NodeCreateMethod::BindMount
        };
        self.device_config
            .as_mut()
            .map_or(Ok(()), |ref mut d| d.pre_fork_setup(mode))
            .map_err(Error::PreForkDeviceSetup)?;

        let ns_ready_signal = SyncPipe::new().map_err(Error::SyncPipeCreation)?;
        let ns_setup_complete = SyncPipe::new().map_err(Error::SyncPipeCreation)?;
        let pid = self.do_clone()?;
        match pid {
            0 => {
                // child
                // Reminder that because we call clone, glibc's stupid getpid
                // cache is not correct.
                // unsafe {
                // println!("child pid is {} instead of {}", nix::unistd::getpid(),
                // nix::sys::syscall::syscall(SYS_getpid as i64));
                // }
                //
                self.run_child(ns_ready_signal, ns_setup_complete);
            }
            _ => {
                // parent
                self.pid = pid;
                self.parent_setup(ns_ready_signal, ns_setup_complete)?;
                for h in self.poststart_hooks.iter() {
                    h.run(
                        self.hook_template
                            .as_ref()
                            .map(|t| t.to_string(Some(self.pid as u64), "started")),
                    )
                    .map_err(Error::HookFailure)?;
                }
            }
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Result<()> {
        loop {
            unsafe {
                let mut status: libc::c_int = 0;
                let ret = libc::waitpid(self.pid, &mut status as *mut _, 0);
                if ret < 0 {
                    let errno = *libc::__errno_location();
                    if errno == libc::EINTR || errno == libc::EAGAIN {
                        continue;
                    }
                    return Err(Error::WaitPidFailed(errno));
                }
                break;
            }
        }
        for h in self.poststop_hooks.iter() {
            h.run(
                self.hook_template
                    .as_ref()
                    .map(|t| t.to_string(Some(self.pid as u64), "stopped")),
            )
            .map_err(Error::HookFailure)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    extern crate libc;
    extern crate nix;
    extern crate tempdir;

    use self::tempdir::TempDir;
    use super::Container;
    use cgroup_namespace::*;
    use mount_namespace::*;
    use net_namespace::EmptyNetNamespace;
    use seccomp_jail::SeccompConfig;
    use seccomp_jail::SeccompJail;
    use std::ffi::CString;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use user_namespace::*;

    fn create_cgroup_type(cg_base: &Path, t: &str) {
        let mut cg_path = PathBuf::from(&cg_base);
        cg_path.push(t);
        fs::create_dir(cg_path.as_path()).unwrap();
        cg_path.push("containers");
        fs::create_dir(cg_path.as_path()).unwrap();
    }

    fn setup_cgroups(temp_dir: &TempDir) -> CGroupNamespace {
        // Cgroup Name
        let temp_path = temp_dir.path();
        create_cgroup_type(&temp_path, "cpu");
        create_cgroup_type(&temp_path, "cpuacct");
        create_cgroup_type(&temp_path, "cpuset");
        create_cgroup_type(&temp_path, "devices");
        create_cgroup_type(&temp_path, "freezer");
        CGroupNamespace::new()
    }

    #[test]
    #[ignore] // Can't run without root.
    fn start_test() {
        let temp_cgdir = TempDir::new("fake_cg").unwrap();
        let argv = vec![
            CString::new("/bin/ls").unwrap(),
            CString::new("-l").unwrap(),
        ];
        let cgroup_namespace = setup_cgroups(&temp_cgdir);
        let mount_namespace = MountNamespace::new(PathBuf::from("/tmp/foo"));
        let mut user_namespace = UserNamespace::new();
        let seccomp_config = SeccompConfig::new("SCMP_ACT_ALLOW").unwrap();
        let seccomp_jail = SeccompJail::new(&seccomp_config).unwrap();
        user_namespace.add_uid_mapping(0, unsafe { libc::getuid() } as u64, 1);
        user_namespace.add_gid_mapping(0, unsafe { libc::getgid() } as u64, 1);
        // TODO(dgreid) - add test with each network namespace
        let mut c = Container::new(
            "asdf",
            argv,
            None,
            Vec::new(),
            Some(cgroup_namespace),
            None,
            Some(mount_namespace),
            Some(Box::new(EmptyNetNamespace::new())),
            Some(user_namespace),
            Vec::new(),
            false,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            Some(seccomp_jail),
            None,
            None,
            true,
        );
        assert_eq!("asdf", c.name());
        assert!(c.start().is_ok());
        assert!(c.wait().is_ok());
    }
}
