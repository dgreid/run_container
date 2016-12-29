extern crate nix;

use self::nix::libc::{gid_t, pid_t, uid_t};

use std::io;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::path::PathBuf;
use std::io::Write;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Nix(nix::Error),
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

pub struct CGroupDirectory {
    path: PathBuf,
}

impl CGroupDirectory {
    pub fn new(base: &Path,
               parent: &str,
               name: &str,
               ctype: &str)
               -> Result<CGroupDirectory, Error> {
        let mut cg_dir = CGroupDirectory { path: PathBuf::from(base) };
        cg_dir.path.push(ctype);
        cg_dir.path.push(parent);
        cg_dir.path.push(name);

        let mut db = fs::DirBuilder::new();

        db.mode(0o700 as u32);
        match db.create(cg_dir.path.as_path()) {
            Ok(()) => {
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

    pub fn chown(&self, cg_uid: Option<uid_t>, cg_gid: Option<gid_t>) -> Result<(), Error> {
        nix::unistd::chown(self.path.as_path(), cg_uid, cg_gid)?;
        Ok(())
    }

    pub fn add_pid(&self, pid: pid_t) -> Result<(), Error> {
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

impl Drop for CGroupDirectory {
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

    use self::tempdir::TempDir;
    use std::fs;
    use std::path::PathBuf;
    use super::CGroupDirectory;

    #[test]
    fn cgroup_dir() {
        let temp_dir = TempDir::new("fake_cg").unwrap();
        let temp_path = temp_dir.path();
        let mut cpu_path = PathBuf::from(temp_dir.path());
        cpu_path.push("cpu");
        fs::create_dir(cpu_path.as_path()).unwrap();
        cpu_path.push("containers");
        fs::create_dir(cpu_path.as_path()).unwrap();
        let cg_dir = CGroupDirectory::new(temp_path, "containers", "testapp", "cpu").unwrap();
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
