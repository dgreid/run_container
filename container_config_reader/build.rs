use std::process::Command;

fn main() {
    println!("Running protoc");
    Command::new("protoc").args(&["--rust_out", ".", "oci_container.proto"])
	.status().unwrap();
}
