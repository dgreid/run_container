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
        UserNamespace { uid_ranges: Vec::new(), gid_ranges: Vec::new() }
    }

    pub fn add_uid_mapping(&mut self, id_inside: usize, id_outside: usize, map_size: usize) {
        self.uid_ranges.push(IdRange { id_inside: id_inside, id_outside: id_outside, map_size : map_size });
    }

    pub fn add_gid_mapping(&mut self, id_inside: usize, id_outside: usize, map_size: usize) {
        self.gid_ranges.push(IdRange { id_inside: id_inside, id_outside: id_outside, map_size : map_size });
    }

    pub fn uid_config_string(&self) -> String {
        let v: Vec<String> = self.uid_ranges.iter()
            .map(|r| format!("{} {} {}", r.id_inside, r.id_outside, r.map_size)).collect();
        v.join(",")
    }

    pub fn gid_config_string(&self) -> String {
        let v: Vec<String> = self.gid_ranges.iter()
            .map(|r| format!("{} {} {}", r.id_inside, r.id_outside, r.map_size)).collect();
        v.join(",")
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
    }

    #[test]
    fn uid_two() {
        let mut u = UserNamespace::new();
        u.add_uid_mapping(0, 10, 1);
        u.add_uid_mapping(100, 500, 20);
        assert_eq!(&u.uid_config_string(), "0 10 1,100 500 20");
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
