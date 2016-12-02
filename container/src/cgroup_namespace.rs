extern crate nix;

use self::nix::libc::pid_t;
use self::nix::sched::*;

use std::collections::HashMap;
use std::io;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::path::PathBuf;
use std::io::Write;

const CGROUPS: &'static [&'static str] = &["cpu",
                                           "cpuacct",
                                           //    "cpuset",
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
    pub fn new(base: &Path, parent: &Path, name: &Path) -> Result<CGroupNamespace, Error> {
        let mut cg_config = CGroupNamespace { cgroup_dirs: HashMap::with_capacity(CGROUPS.len()) };
        for cgroup in CGROUPS {
            let cg = CGroupDir::new(&base, &parent, &name, cgroup)?;
            CGroupNamespace::initialize_cgroup(&cg, cgroup)?;
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
        // Now that the process is in each cgroup, enter a new cgroup namespace
        nix::sched::unshare(CLONE_NEWCGROUP)?;
        Ok(())
    }

    fn initialize_cgroup(cg: &CGroupDir, name: &str) -> Result<(), Error> {
        match name {
            "cpu" => Ok(()),
            "cpuacct" => Ok(()),
            "cpuset" => Ok(()),
            "freezer" => Ok(()),
            "devices" => CGroupNamespace::initialize_device_cgroup(cg),
            _ => Err(Error::InvalidCGroup),
        }
    }

    fn initialize_device_cgroup(cg: &CGroupDir) -> Result<(), Error> {
        cg.write_file("devices.deny", "a *:* rwm")?;
        cg.write_file("devices.allow", "c 1:3 rwm")?; // null
        cg.write_file("devices.allow", "c 1:5 rwm")?; // zero
        cg.write_file("devices.allow", "c 1:8 rwm")?; // random
        cg.write_file("devices.allow", "c 1:9 rwm")?; // urandom
        Ok(())
    }
}

struct CGroupDir {
    path: PathBuf,
}

impl CGroupDir {
    pub fn new(base: &Path, parent: &Path, name: &Path, ctype: &str) -> Result<CGroupDir, Error> {
        let mut cg_dir = CGroupDir { path: PathBuf::from(base) };
        cg_dir.path.push(ctype);
        cg_dir.path.push(parent);
        cg_dir.path.push(name);

        let mut db = fs::DirBuilder::new();
        db.mode(0o700 as u32);
        match db.create(cg_dir.path.as_path()) {
            Ok(()) => Ok(cg_dir),
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
    extern crate tempdir;

    use self::tempdir::TempDir;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use super::CGroupDir;

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
                                    "cpu")
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
}
