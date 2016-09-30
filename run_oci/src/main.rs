extern crate container;
extern crate container_config_reader;

use container_config_reader::container_from_oci_config;

use std::env;
use std::path::Path;

fn main() {
    let argv: Vec<String> = env::args().collect();

    let mut c = container_from_oci_config(Path::new(&argv[1])).expect("Failed to parse config");

    println!("starting {}", c.name());
    c.start().unwrap();
    c.wait().unwrap();
    println!("done");
}
