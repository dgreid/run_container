extern crate nix;
extern crate container;

use container::container::Container;
use container::mount_namespace::*;
use container::net_namespace::EmptyNetNamespace;
use container::user_namespace::UserNamespace;

use self::nix::mount::*;
use self::nix::unistd::{getuid, getgid};
use std::ffi::CString;
use std::path::PathBuf;

fn main() {
    let proc_opts = Vec::new();
    let mut mount_namespace = MountNamespace::new(PathBuf::from("/tmp/foo"));
    mount_namespace.add_mount(None, PathBuf::from("proc"), Some("proc".to_owned()),
                              MS_REC, proc_opts).unwrap();

    let mut user_namespace = UserNamespace::new();
    user_namespace.add_uid_mapping(0, getuid() as usize, 1);
    user_namespace.add_gid_mapping(0, getgid() as usize, 1);

    let mut c = Container::new("asdf", vec![ CString::new("/bin/bash").unwrap() ],
                               mount_namespace, Box::new(EmptyNetNamespace::new()), user_namespace);
    println!("starting {}", c.name());
    c.start().unwrap();
    c.wait().unwrap();
    println!("done");
}
