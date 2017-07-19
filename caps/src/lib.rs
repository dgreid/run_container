extern crate libc;
extern crate libcap_ffi;

use libcap_ffi::*;

use std::ffi::CString;
use std::fs::File;
use std::io::Read;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Failed to add a capability to the ambient caps.
    AddingAmbientCap(i32, i32),
    /// Ambient capabilites are a reqired kernel feature.
    AmbientCapsUnsupportedInKernel,
    /// Failed clearing ambient capabilities.
    ClearingAmbientCaps(i32),
    /// `cap_set_flag` failed.
    ConfiguringCaps,
    /// `cap_init` failed with the specified errno.
    CreatingCaps(i32),
    /// Failed to drop the specified cap from the bounding set.
    DroppingBoundingCap(i32, i32),
    /// Failed to read the last valid capability from /proc.
    GettingLastValidCap,
    /// The capability name specified is invalid or doesn't exist.
    InvalidCapability,
    /// Setting the securebits prctl to the first value failed with the provided errno.
    SecureBits(usize, i32),
    /// Setting the capabilities failed with the given errno.
    SettingCaps(i32),
    /// PR_SET_KEEPCAPS failed.
    SettingKeepCaps(i32),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Eq, Hash, PartialEq)]
pub enum CapType {
    Ambient,
    Bounding,
    Effective,
    Inheritable,
    Permitted,
}

type Capability = libcap_ffi::cap_value_t;
type CapMap = std::collections::HashMap<CapType, Vec<Capability>>;

fn cap_ambient_supported() -> bool {
    unsafe {
        // Calling prctl is safe, it doesn't touch memory.
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET,
            libcap_ffi::CAP_CHOWN,
            0,
            0,
        ) >= 0
    }
}

fn cap_from_name(name: &str) -> Result<Capability> {
    let cap_name = CString::new(name).map_err(|_| Error::InvalidCapability)?;
    let mut cap_val: libcap_ffi::cap_value_t = libcap_ffi::CAP_LAST_CAP as i32;
    let ret = unsafe {
        // `cap_from_name` is safe, it only reads the passed string.
        libcap_ffi::cap_from_name(cap_name.as_ptr() as *const _, &mut cap_val as *mut _)
    };
    if ret == -1 {
        return Err(Error::InvalidCapability);
    }
    Ok(cap_val)
}

fn get_last_valid_cap() -> Result<Capability> {
    let mut f = File::open("/proc/sys/kernel/cap_last_cap").map_err(|_| {
        Error::GettingLastValidCap
    })?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(
        |_| Error::GettingLastValidCap,
    )?;
    s.pop(); // Remove trailing newline.
    Ok(s.parse::<i32>().map_err(|_| Error::GettingLastValidCap)?)
}

fn cap_flag_val(cap: CapType) -> cap_flag_t {
    match cap {
        CapType::Ambient => panic!("No capability flag for Ambient caps."),
        CapType::Bounding => panic!("No capability flag for Bounding caps."),
        CapType::Effective => cap_flag_t::CAP_EFFECTIVE,
        CapType::Inheritable => cap_flag_t::CAP_INHERITABLE,
        CapType::Permitted => cap_flag_t::CAP_PERMITTED,
    }
}

/// Capability configuration for a process.
///
/// * caps - A map of the capabilities allocated to the process.
/// * securebits_unlock_mask - A mask of the securebits to leave unlocked see capabilities(7).
pub struct CapConfig {
    caps: CapMap,
    securebits_unlock_mask: usize,
}

impl CapConfig {
    pub fn new() -> Result<CapConfig> {
        if !cap_ambient_supported() {
            return Err(Error::AmbientCapsUnsupportedInKernel);
        }
        Ok(CapConfig { caps: CapMap::new(), securebits_unlock_mask: 0 })
    }

    pub fn securebits_unlock_mask(&mut self, securebits_unlock_mask: usize) {
        self.securebits_unlock_mask = securebits_unlock_mask;
    }

    pub fn set_caps(&mut self, cap_type: CapType, whitelist: &[String]) -> Result<()> {
        let mut caps = Vec::new();
        for cap_str in whitelist {
            let cap = cap_from_name(cap_str)?;
            caps.push(cap);
        }
        self.caps.insert(cap_type, caps);
        Ok(())
    }

    pub fn drop_caps(&self) -> Result<()> {
        let mut caps = Caps::new()?;
        let empty_caps = Vec::new();

        let effective = self.caps.get(&CapType::Effective).unwrap_or(&empty_caps);
        caps.set_caps(CapType::Effective, effective)?;
        let permitted = self.caps.get(&CapType::Permitted).unwrap_or(&empty_caps);
        caps.set_caps(CapType::Permitted, permitted)?;
        let inheritable = self.caps.get(&CapType::Inheritable).unwrap_or(&empty_caps);
        caps.set_caps(CapType::Inheritable, inheritable)?;

        caps.apply()?;

        self.add_ambient_caps()?;
        Ok(())
    }

    pub fn drop_bounding_caps(&self) -> Result<()> {
        unsafe {
            // `prctl` is safe to call, it doesn't touch memory.
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1) < 0 {
                return Err(Error::SettingKeepCaps(*libc::__errno_location()));
            }
        }

        self.configure_secure_bits()?;

        let last_valid_cap = get_last_valid_cap()?;
        for cap in 0..last_valid_cap {
            if let Some(ref bcaps) = self.caps.get(&CapType::Bounding) {
                if bcaps.contains(&cap) {
                    continue;
                }
            }
            unsafe {
                // `prctl` is safe to call, it doesn't touch memory.
                if libc::prctl(libc::PR_CAPBSET_DROP, cap) < 0 {
                    return Err(Error::DroppingBoundingCap(cap, *libc::__errno_location()));
                }
            }
        }
        Ok(())
    }

    fn configure_secure_bits(&self) -> Result<()> {
        const SECURE_BITS_NO_AMBIENT: usize =  0x15;
        const SECURE_LOCKS_NO_AMBIENT: usize = SECURE_BITS_NO_AMBIENT << 1;

        let securebits =
            (SECURE_BITS_NO_AMBIENT | SECURE_LOCKS_NO_AMBIENT) & !self.securebits_unlock_mask;
        if securebits == 0 {
            return Ok(());
        }
        unsafe {
            // `prctl` is safe to call, it doesn't touch memory.
            if libc::prctl(libc::PR_SET_SECUREBITS, securebits) < 0 {
                return Err(Error::SecureBits(securebits, *libc::__errno_location()));
            }
        }
        Ok(())
    }

    fn add_ambient_caps(&self) -> Result<()> {
        unsafe {
            //`prctl` is safe to call, it doesn't touch memory.
            if libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
            {
                return Err(Error::ClearingAmbientCaps(*libc::__errno_location()));
            }

            if let Some(acaps) = self.caps.get(&CapType::Bounding) {
                for cap in acaps {
                    if libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE,
                        *cap,
                        0,
                        0,
                    ) != 0
                    {
                        return Err(Error::AddingAmbientCap(*cap, *libc::__errno_location()));
                    }
                }
            }
        }
        Ok(())
    }
}

struct Caps {
    caps: cap_t,
}

impl Caps {
    pub fn new() -> Result<Caps> {
        unsafe {
            // Using cap_init for initialization is safe, the value returned is checked to be
            // non-null.
            let caps = cap_init();
            if caps.is_null() {
                return Err(Error::CreatingCaps(*libc::__errno_location()));
            }
            Ok(Caps { caps: caps })
        }
    }

    pub fn set_caps(&mut self, cap_type: CapType, caps: &[Capability]) -> Result<()> {
        unsafe {
            // `cap_set_flag` is safe, it will only read the caps array.
            if cap_set_flag(
                self.caps,
                cap_flag_val(cap_type),
                caps.len() as i32,
                caps.as_ptr() as *const _,
                cap_flag_value_t::CAP_SET,
            ) < 0
            {
                return Err(Error::ConfiguringCaps);
            }
        }
        Ok(())
    }

    pub fn apply(&self) -> Result<()> {
        unsafe {
            // Calling cap_set_proc is safe. The kernel will only read from the capability arrays.
            if cap_set_proc(self.caps) < 0 {
                return Err(Error::SettingCaps(*libc::__errno_location()));
            }
        }
        Ok(())
    }
}

impl Drop for Caps {
    fn drop(&mut self) {
        unsafe {
            // This will free the memory `caps` points to.  It's safe because there aren't any more
            // references to this memory when drop runs.
            cap_free(self.caps as *mut _);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_create() {
        let mut caps = Caps::new().unwrap();
        assert!(
            caps.set_caps(CapType::Permitted, &[CAP_CHOWN as Capability])
                .is_ok()
        );
    }

    #[test]
    fn caps_drop_all() {
        let caps = Caps::new().unwrap();
        caps.apply().unwrap();
    }

    #[test]
    fn last_valid() {
        assert!(get_last_valid_cap().is_ok());
    }

    #[test]
    fn from_name_valid_cap() {
        assert_eq!(Ok(libcap_ffi::CAP_CHOWN as i32), cap_from_name("CAP_CHOWN"));
    }

    #[test]
    fn from_name_invalid_cap() {
        unsafe {
            assert_eq!(
                -1,
                libcap_ffi::cap_from_name(
                    b"CAP_NOTREALLY\0".as_ptr() as *const std::os::raw::c_char,
                    std::ptr::null_mut(),
                )
            );
        }
    }
}
