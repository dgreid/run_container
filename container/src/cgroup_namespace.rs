extern crate nix;

use self::nix::libc::pid_t;
use self::nix::libc::uid_t;
use self::nix::mount::*;
use self::nix::sched::*;
use self::nix::unistd::getuid;

use std::collections::HashMap;
use std::io;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::path::PathBuf;
use std::io::Read;
use std::io::Write;

const CGROUPS: &'static [&'static str] = &["cpu",
                                           "cpuacct",
                                           "cpuset",
                                           "freezer",
                                           "devices"];

pub struct CGroupNamespace {
    cgroup_dirs: HashMap<&'static str, CGroupDir>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Nix(nix::Error),
    CGroupCreateError,
    InvalidCGroup,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::Nix(err)
    }
}

impl CGroupNamespace {
    pub fn new(base: &Path, parent: &Path, name: &Path, root_uid: uid_t)
            -> Result<CGroupNamespace, Error> {
        let mut cg_config = CGroupNamespace { cgroup_dirs: HashMap::with_capacity(CGROUPS.len()) };
        for cgroup in CGROUPS {
            let cg = CGroupDir::new(&base, &parent, &name, cgroup, root_uid)?;
            CGroupNamespace::initialize_cgroup(&cg, cgroup, base, parent)?;
            cg_config.cgroup_dirs.insert(cgroup, cg);
        }
        Ok(cg_config)
    }

    pub fn join_cgroups(&mut self, pid: pid_t) -> Result<(), Error> {
        // Put the process in each cgroup's tasks file
        for cgroup in CGROUPS {
            self.cgroup_dirs[cgroup].enter(pid)?;
        }
        Ok(())
    }

    pub fn enter(&self) -> Result<(), Error> {
        // Now that the process is in each cgroup, enter a new cgroup namespace.
        nix::sched::unshare(CLONE_NEWCGROUP)?;
        // Not allowed to mkdir in sysfs because it is owned by real root.
        // Create a tmpfs so that the cgroup dirs can be created.
        nix::mount::mount(Some(Path::new("")),
                          Path::new("/sys/fs/cgroup"),
                          Some(Path::new("tmpfs")),
                          MS_NODEV | MS_NOEXEC | MS_MGC_VAL,
                          None::<&Path>)?;
        for cgroup in CGROUPS {
            let dest = &format!("/sys/fs/cgroup/{}", cgroup);
            let destination = Path::new(dest);
            fs::create_dir(destination).ok();
            nix::mount::mount(Some(Path::new("")),
                              destination,
                              Some(Path::new("cgroup")),
                              MsFlags::empty(),
                              Some(Path::new(cgroup)))?;
        }
        Ok(())
    }

    fn initialize_cgroup(cg: &CGroupDir, name: &str, base: &Path, parent: &Path) -> Result<(), Error> {
        match name {
            "cpu" => Ok(()),
            "cpuacct" => Ok(()),
            "cpuset" => CGroupNamespace::initialize_cpuset_cgroup(cg, base, parent),
            "freezer" => Ok(()),
            "devices" => CGroupNamespace::initialize_device_cgroup(cg),
            _ => Err(Error::InvalidCGroup),
        }
    }

    fn initialize_cpuset_cgroup(cg: &CGroupDir, base: &Path, parent: &Path) -> Result<(), Error> {
        let mut cpus_path = PathBuf::from(base);
        cpus_path.push("cpuset");
        cpus_path.push(parent);
        cpus_path.push("cpus");
        let mut cpus_file = fs::File::open(cpus_path.as_path()).unwrap();
        let mut cpus = String::new();
        cpus_file.read_to_string(&mut cpus)?;
        cg.write_file("cpus", &cpus)?;

        let mut mems_path = PathBuf::from(base);
        mems_path.push("cpuset");
        mems_path.push(parent);
        mems_path.push("mems");
        let mut mems_file = fs::File::open(mems_path.as_path()).unwrap();
        let mut mems = String::new();
        mems_file.read_to_string(&mut mems)?;
        cg.write_file("mems", &mems)?;
        Ok(())
    }

    fn initialize_device_cgroup(cg: &CGroupDir) -> Result<(), Error> {
        // This is only possible if we start from a privileged user.
        if getuid() == 0 {
            cg.write_file("devices.deny", "a *:* rwm")?;
            cg.write_file("devices.allow", "c 1:3 rwm")?; // null
            cg.write_file("devices.allow", "c 1:5 rwm")?; // zero
            cg.write_file("devices.allow", "c 1:8 rwm")?; // random
            cg.write_file("devices.allow", "c 1:9 rwm")?; // urandom
        }
        Ok(())
    }
}

struct CGroupDir {
    path: PathBuf,
}

impl CGroupDir {
    pub fn new(base: &Path, parent: &Path, name: &Path, ctype: &str, uid: uid_t)
            -> Result<CGroupDir, Error> {
        let mut cg_dir = CGroupDir { path: PathBuf::from(base) };
        cg_dir.path.push(ctype);
        cg_dir.path.push(parent);
        cg_dir.path.push(name);

        let mut db = fs::DirBuilder::new();
        db.mode(0o700 as u32);
        match db.create(cg_dir.path.as_path()) {
            Ok(()) => {
                nix::unistd::chown(cg_dir.path.as_path(), Some(uid), None)?;
                Ok(cg_dir)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(cg_dir)
                } else {
                    Err(Error::Io(e))
                }
            }
        }
    }

    pub fn enter(&self, pid: pid_t) -> Result<(), Error> {
        let mut tasks_path = PathBuf::from(&self.path);
        tasks_path.push("tasks");

        let mut tasks_file = fs::File::create(tasks_path.as_path())?;
        tasks_file.write_all(pid.to_string().as_bytes())?;
        Ok(())
    }

    pub fn write_file(&self, name: &str, val: &str) -> Result<(), Error> {
        let mut file_path = PathBuf::from(&self.path);
        file_path.push(name);

        let mut file = fs::File::create(file_path.as_path())?;
        file.write_all(val.as_bytes())?;
        Ok(())
    }
}

impl Drop for CGroupDir {
    fn drop(&mut self) {
        match fs::remove_dir(self.path.as_path()) {
            Ok(()) => (),
            Err(_) => (),
        }
    }
}

#[cfg(test)]
mod test {
    extern crate nix;
    extern crate tempdir;

    use self::nix::libc::pid_t;
    use self::nix::unistd::getuid;
    use self::tempdir::TempDir;
    use std::fs;
    use std::io::Read;
    use std::io::Write; use std::path::Path;
    use std::path::PathBuf;
    use super::CGroupDir;
    use super::CGroupNamespace;

    #[test]
    fn cgroup_dir() {
        let temp_dir = TempDir::new("fake_cg").unwrap();
        let temp_path = temp_dir.path();
        let mut cpu_path = PathBuf::from(temp_dir.path());
        cpu_path.push("cpu");
        fs::create_dir(cpu_path.as_path()).unwrap();
        cpu_path.push("containers");
        fs::create_dir(cpu_path.as_path()).unwrap();
        let cg_dir = CGroupDir::new(temp_path,
                                    Path::new("containers"),
                                    Path::new("testapp"),
                                    "cpu",
                                    0)
            .unwrap();
        let mut cg_path = PathBuf::from(temp_path);
        cg_path.push("cpu/containers/testapp");
        assert!(cg_path.exists());
        cg_dir.write_file("foo.allow", "some_string").unwrap();
        let mut new_file = cg_path.clone();
        new_file.push("foo.allow");
        assert!(new_file.exists());
        fs::remove_file(new_file.as_path()).unwrap();
        drop(cg_dir);
        assert!(!cg_path.exists());
    }

    #[test]
    fn cgroup_create() {
        const CGROUPS: &'static [&'static str] =
            &["cpu", "cpuacct", "cpuset", "freezer", "devices"];
        let temp_dir = TempDir::new("fake_cg").unwrap();
        let temp_path = temp_dir.path();
        for cgroup in CGROUPS {
            let mut cg_path = PathBuf::from(temp_path);
            cg_path.push(cgroup);
            fs::create_dir(cg_path.as_path()).unwrap();
            cg_path.push("subdir");
            fs::create_dir(cg_path.as_path()).unwrap();
        }
        let mut parent_cpus_path = PathBuf::from(temp_path);
        parent_cpus_path.push("cpuset/subdir/cpus");
        let mut parent_cpus_file = fs::File::create(parent_cpus_path.as_path()).unwrap();
        parent_cpus_file.write_all(b"0-4").unwrap();

        let mut parent_mems_path = PathBuf::from(temp_path);
        parent_mems_path.push("cpuset/subdir/mems");
        let mut parent_mems_file = fs::File::create(parent_mems_path.as_path()).unwrap();
        parent_mems_file.write_all(b"0").unwrap();

        let mut cg = CGroupNamespace::new(temp_dir.path(), Path::new("subdir"), Path::new("oci"), 0)
            .unwrap();
        cg.join_cgroups(555 as pid_t).unwrap();
        for cgroup in CGROUPS {
            let mut cg_path = PathBuf::from(temp_path);
            cg_path.push(cgroup);
            cg_path.push("subdir");
            cg_path.push("oci");
            assert!(cg_path.exists());
            cg_path.push("tasks");
            assert!(cg_path.exists());

            let mut tasks_file = fs::File::open(cg_path.as_path()).unwrap();
            let mut s = String::new();
            tasks_file.read_to_string(&mut s).unwrap();
            assert!(s == "555");
        }

        if getuid() == 0 {
            let mut device_list_path = PathBuf::from(temp_path);
            device_list_path.push("devices/subdir/oci/devices.deny");
            let mut devices_list_file = fs::File::open(device_list_path.as_path()).unwrap();
            let mut denied = String::new();
            devices_list_file.read_to_string(&mut denied).unwrap();
            assert!(denied == "a *:* rwm");
        }

        let mut cpus_path = PathBuf::from(temp_path);
        cpus_path.push("cpuset/subdir/oci/cpus");
        let mut cpus_file = fs::File::open(cpus_path.as_path()).unwrap();
        let mut cpus = String::new();
        cpus_file.read_to_string(&mut cpus).unwrap();
        assert!(cpus == "0-4");

        let mut mems_path = PathBuf::from(temp_path);
        mems_path.push("cpuset/subdir/oci/mems");
        let mut mems_file = fs::File::open(mems_path.as_path()).unwrap();
        let mut mems = String::new();
        mems_file.read_to_string(&mut mems).unwrap();
        assert!(mems == "0");
    }
}
