extern crate container;
extern crate container_config_reader;

use container_config_reader::container_from_oci_config;
use container::net_namespace::NatNetNamespace;

use std::env;
use std::path::Path;

fn main() {
    let argv: Vec<String> = env::args().collect();

    let mut c = container_from_oci_config(Path::new(&argv[1])).expect("Failed to parse config");

    let net_ns = Box::new(NatNetNamespace::new(vec!["eth0".to_string(), "wlan0".to_string()],
                                               "10.1.1.1/24".to_string()));
    c.set_net_namespace(net_ns);
    println!("starting {}", c.name());
    c.start().unwrap();
    c.wait().unwrap();
    println!("done");
}
