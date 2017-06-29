extern crate caps;
extern crate libc;

use caps::{CapConfig, CapType};

use std::ffi::CString;
use std::os::raw::c_char;

fn show_usage(arg0: &str) {
    println!("Run a given program with only whitelisted capabilities.");
    println!("Usage: {} cap1 cap2 ... capN -- program args", arg0);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args[1] == "--help" || args[1] == "-h" {
        show_usage(&args[0]);
        return;
    }

    let div_index = match args.iter().rposition(|ref s| *s == "--") {
        Some(i) => i,
        None => {
            show_usage(&args[0]);
            return;
        }
    };

    let whitelist = &args[1..div_index];

    let mut caps = CapConfig::new().unwrap();
    caps.set_caps(CapType::Ambient, whitelist).unwrap();
    caps.set_caps(CapType::Bounding, whitelist).unwrap();
    caps.set_caps(CapType::Effective, whitelist).unwrap();
    caps.set_caps(CapType::Inheritable, whitelist).unwrap();
    caps.set_caps(CapType::Permitted, whitelist).unwrap();
    caps.drop_bounding_caps().unwrap();
    caps.drop_caps().unwrap();

    let pargs = &args[(div_index + 1)..];
    let path = CString::new(pargs[0].clone()).unwrap();
    let mut argvec: Vec<CString> = Vec::new();
    for arg in pargs[..].iter() {
        argvec.push(CString::new(arg.clone()).unwrap());
    }
    let args_p = to_exec_array(&argvec[..]);
    unsafe {
        // This won't return so it doesn't matter if it's safe.
        libc::execv(path.as_ptr(), args_p.as_ptr());
    }
}

fn to_exec_array(args: &[CString]) -> Vec<*const c_char> {
    use std::ptr;
    use libc::c_char;

    let mut args_p: Vec<*const c_char> = args.iter().map(|s| s.as_ptr()).collect();
    args_p.push(ptr::null());
    args_p
}
