extern crate nix;

use self::nix::sys::ioctl::libc::pid_t;
use std::fs;
use std::io;
use std::io::Write;

struct IdRange {
    id_inside: usize,
    id_outside: usize,
    map_size: usize,
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

    pub fn add_uid_mapping(&mut self, id_inside: usize, id_outside: usize, map_size: usize) {
        self.uid_ranges
            .push(IdRange {
                      id_inside: id_inside,
                      id_outside: id_outside,
                      map_size: map_size,
                  });
    }

    pub fn add_gid_mapping(&mut self, id_inside: usize, id_outside: usize, map_size: usize) {
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
        v.join(",")
    }

    pub fn gid_config_string(&self) -> String {
        let v: Vec<String> = self.gid_ranges
            .iter()
            .map(|r| format!("{} {} {}", r.id_inside, r.id_outside, r.map_size))
            .collect();
        v.join(",")
    }

    pub fn get_external_uid(&self, id: usize) -> Option<usize> {
        for map in &self.uid_ranges {
            if id >= map.id_inside && id < map.id_inside + map.map_size {
                return Some(map.id_outside + (id - map.id_inside));
            }
        }
        None
    }

    pub fn configure(&self, pid: pid_t, disable_set_groups: bool) -> Result<(), io::Error> {
        let mut uid_file = fs::OpenOptions::new().write(true)
            .read(false)
            .create(false)
            .open(format!("/proc/{}/uid_map", pid))?;
        uid_file.write_all(self.uid_config_string().as_bytes())?;

        if disable_set_groups {
            // Must disable setgroups before writing gid map if running as a normal user
            let mut setgroups_file = fs::OpenOptions::new().write(true)
                .read(false)
                .create(false)
                .open(format!("/proc/{}/setgroups", pid))?;
            setgroups_file.write_all(b"deny")?;
        }

        let mut gid_file = fs::OpenOptions::new().write(true)
            .read(false)
            .create(false)
            .open(format!("/proc/{}/gid_map", pid))?;
        gid_file.write_all(self.gid_config_string().as_bytes())?;

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
        assert_eq!(&u.uid_config_string(), "0 10 1,100 500 20");
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
        assert_eq!(&u.gid_config_string(), "0 10 1,100 500 20,1000 1500 220");
    }
}
