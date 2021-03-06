extern crate libc;

use self::libc::pid_t;
use std;
use std::fs;
use std::io;
use std::io::Write;

#[derive(Debug)]
pub enum Error {
    GroupMaps(io::Error),
    SetGroups(io::Error),
    UserMaps(io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

struct IdRange {
    id_inside: u64,
    id_outside: u64,
    map_size: u64,
}

pub struct UserNamespace {
    uid_ranges: Vec<IdRange>,
    gid_ranges: Vec<IdRange>,
}

impl UserNamespace {
    pub fn new() -> Self {
        UserNamespace {
            uid_ranges: Vec::new(),
            gid_ranges: Vec::new(),
        }
    }

    pub fn add_uid_mapping(&mut self, id_inside: u64, id_outside: u64, map_size: u64) {
        self.uid_ranges
            .push(IdRange {
                      id_inside: id_inside,
                      id_outside: id_outside,
                      map_size: map_size,
                  });
    }

    pub fn add_gid_mapping(&mut self, id_inside: u64, id_outside: u64, map_size: u64) {
        self.gid_ranges
            .push(IdRange {
                      id_inside: id_inside,
                      id_outside: id_outside,
                      map_size: map_size,
                  });
    }

    pub fn uid_config_string(&self) -> String {
        let v: Vec<String> = self.uid_ranges
            .iter()
            .map(|r| format!("{} {} {}", r.id_inside, r.id_outside, r.map_size))
            .collect();
        v.join("\n")
    }

    pub fn gid_config_string(&self) -> String {
        let v: Vec<String> = self.gid_ranges
            .iter()
            .map(|r| format!("{} {} {}", r.id_inside, r.id_outside, r.map_size))
            .collect();
        v.join("\n")
    }

    pub fn get_external_uid(&self, id: u64) -> Option<u64> {
        for map in &self.uid_ranges {
            if id >= map.id_inside && id < map.id_inside + map.map_size {
                return Some(map.id_outside + (id - map.id_inside));
            }
        }
        None
    }

    pub fn get_external_gid(&self, id: u64) -> Option<u64> {
        for map in &self.gid_ranges {
            if id >= map.id_inside && id < map.id_inside + map.map_size {
                return Some(map.id_outside + (id - map.id_inside));
            }
        }
        None
    }

    pub fn configure(&self, pid: pid_t, disable_set_groups: bool) -> Result<()> {
        let mut uid_file = fs::OpenOptions::new().write(true)
            .read(false)
            .create(false)
            .open(format!("/proc/{}/uid_map", pid))
            .map_err(Error::UserMaps)?;
        uid_file.write_all(self.uid_config_string().as_bytes())
            .map_err(Error::UserMaps)?;

        if disable_set_groups {
            // Must disable setgroups before writing gid map if running as a normal user
            let mut setgroups_file = fs::OpenOptions::new().write(true)
                .read(false)
                .create(false)
                .open(format!("/proc/{}/setgroups", pid))
                .map_err(Error::SetGroups)?;
            setgroups_file.write_all(b"deny")
                .map_err(Error::SetGroups)?;
        }

        let mut gid_file = fs::OpenOptions::new().write(true)
            .read(false)
            .create(false)
            .open(format!("/proc/{}/gid_map", pid))
            .map_err(Error::GroupMaps)?;
        gid_file.write_all(self.gid_config_string().as_bytes())
            .map_err(Error::GroupMaps)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::UserNamespace;

    #[test]
    fn uid_one() {
        let mut u = UserNamespace::new();
        u.add_uid_mapping(0, 10, 1);
        assert_eq!(&u.uid_config_string(), "0 10 1");
        assert_eq!(u.get_external_uid(0), Some(10));
        assert_eq!(u.get_external_uid(1), None);
    }

    #[test]
    fn uid_two() {
        let mut u = UserNamespace::new();
        u.add_uid_mapping(0, 10, 1);
        u.add_uid_mapping(100, 500, 20);
        assert_eq!(&u.uid_config_string(), "0 10 1\n100 500 20");
        assert_eq!(u.get_external_uid(0), Some(10));
        assert_eq!(u.get_external_uid(1), None);
        assert_eq!(u.get_external_uid(100), Some(500));
        assert_eq!(u.get_external_uid(101), Some(501));
        assert_eq!(u.get_external_uid(119), Some(519));
        assert_eq!(u.get_external_uid(120), None);
    }

    #[test]
    fn gid_three() {
        let mut u = UserNamespace::new();
        u.add_uid_mapping(0, 10, 1);
        u.add_gid_mapping(0, 10, 1);
        u.add_gid_mapping(100, 500, 20);
        u.add_gid_mapping(1000, 1500, 220);
        assert_eq!(&u.uid_config_string(), "0 10 1");
        assert_eq!(&u.gid_config_string(), "0 10 1\n100 500 20\n1000 1500 220");
    }
}
