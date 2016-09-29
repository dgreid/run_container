extern crate nix;

mod container;
mod mount_namespace;
mod sync_pipe;
mod user_namespace;

use container::Container;
use mount_namespace::*;
use user_namespace::UserNamespace;

use self::nix::mount::*;
use self::nix::unistd::{getuid, getgid};
use std::ffi::CString;
use std::path::Path;

fn main() {
    let proc_opts = Vec::new();
    let mut mount_namespace = MountNamespace::new(Path::new("/tmp/foo"));
    mount_namespace.add_mount(None, Path::new("proc"), Some("proc"), MS_REC, &proc_opts).unwrap();

    let mut user_namespace = UserNamespace::new();
    user_namespace.add_uid_mapping(0, getuid() as usize, 1);
    user_namespace.add_gid_mapping(0, getgid() as usize, 1);

    let mut c = Container::new("asdf", vec![ CString::new("/bin/bash").unwrap() ],
                               &mount_namespace, &user_namespace);
    println!("starting {}", c.name());
    c.start().unwrap();
    c.wait().unwrap();
    println!("done");
}
