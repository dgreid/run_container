extern crate nix;
extern crate seccomp_sys;

use syscall_defines;

use std::collections::HashMap;

pub struct SeccompConfig {
    default_action: Action,
    rules: HashMap<SyscallRule, Vec<seccomp_sys::scmp_arg_cmp>>,
}

pub struct SeccompJail {
    ctx: *mut seccomp_sys::scmp_filter_ctx,
}

#[derive(Hash, Eq, PartialEq)]
struct SyscallRule {
    name: String,
    action: String,
}

#[derive(Debug)]
pub enum Error {
    InvalidAction(String),
    InvalidCmpOp,
    SeccompInitFail,
    SeccompRuleAddFail,
    SeccompLoadFail,
    InvalidSyscall,
}

enum Action {
    Allow,
    Kill,
    Trap,
    Errno(i32),
    Trace(u32),
}

fn action_number(action: &Action) -> u32 {
    match *action {
        Action::Allow => seccomp_sys::SCMP_ACT_ALLOW,
        Action::Kill => seccomp_sys::SCMP_ACT_KILL,
        Action::Trap => seccomp_sys::SCMP_ACT_TRAP,
        Action::Errno(x) => seccomp_sys::SCMP_ACT_ERRNO(x as u32),
        Action::Trace(x) => seccomp_sys::SCMP_ACT_TRACE(x),
    }
}

fn action_from_string(act_str: &str) -> Result<Action, Error> {
    match act_str {
        "SCMP_ACT_KILL" => Ok(Action::Kill),
        "SCMP_ACT_TRAP" => Ok(Action::Trap),
        "SCMP_ACT_ERRNO" => Ok(Action::Errno(1)),
        "SCMP_ACT_TRACE" => Ok(Action::Trace(1)), // TODO
        "SCMP_ACT_ALLOW" => Ok(Action::Allow),
        _ => Err(Error::InvalidAction(act_str.to_string())),
    }
}

fn op_from_string(op_str: &str) -> Result<seccomp_sys::scmp_compare, Error> {
    match op_str {
        "SCMP_CMP_NE" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_NE),
        "SCMP_CMP_LT" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_LT),
        "SCMP_CMP_LE" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_LE),
        "SCMP_CMP_EQ" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_EQ),
        "SCMP_CMP_GE" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_GE),
        "SCMP_CMP_GT" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_GT),
        "SCMP_CMP_MASKED_EQ" => Ok(seccomp_sys::scmp_compare::SCMP_CMP_MASKED_EQ),
        _ => Err(Error::InvalidCmpOp),
    }
}

impl SeccompConfig {
    pub fn new(default_action: &str) -> Result<SeccompConfig, Error> {
        let default_action = action_from_string(default_action)?;
        Ok(SeccompConfig {
            default_action: default_action,
            rules: HashMap::new(),
        })
    }

    pub fn add_rule(
        &mut self,
        syscall_name: &str,
        action: &str,
        arg_index: Option<u32>,
        val: Option<u64>,
        val2: Option<u64>,
        op: Option<&str>,
    ) -> Result<(), Error> {
        let hash_key = SyscallRule {
            name: syscall_name.to_string(),
            action: action.to_string(),
        };
        let ops = self.rules.entry(hash_key).or_insert_with(Vec::new);
        if let (Some(op), Some(arg_index)) = (op, arg_index) {
            ops.push(seccomp_sys::scmp_arg_cmp {
                arg: arg_index,
                op: op_from_string(op)?,
                datum_a: val.unwrap_or(0),
                datum_b: val2.unwrap_or(0),
            });
        }
        Ok(())
    }
}

impl SeccompJail {
    pub fn new(config: &SeccompConfig) -> Result<SeccompJail, Error> {
        unsafe {
            let context = seccomp_sys::seccomp_init(action_number(&config.default_action));
            if context.is_null() {
                return Err(Error::SeccompInitFail);
            }
            for (key, ops) in &config.rules {
                let syscall_number =
                    syscall_defines::from_name(&key.name).map_err(|_| Error::InvalidSyscall)?;
                let action = action_number(&action_from_string(&key.action)?);
                let ret = seccomp_sys::seccomp_rule_add_array(
                    context,
                    action,
                    syscall_number as i32,
                    ops.len() as u32,
                    ops.as_slice().as_ptr(),
                );
                if ret != 0 {
                    seccomp_sys::seccomp_release(context);
                    return Err(Error::SeccompRuleAddFail);
                }
            }
            Ok(SeccompJail { ctx: context })
        }
    }

    pub fn enter(&self) -> Result<(), Error> {
        let ret = unsafe { seccomp_sys::seccomp_load(self.ctx) };
        if ret == 0 {
            Ok(())
        } else {
            Err(Error::SeccompLoadFail)
        }
    }
}

impl Drop for SeccompJail {
    fn drop(&mut self) {
        unsafe { seccomp_sys::seccomp_release(self.ctx) }
    }
}

#[cfg(test)]
mod test {
    extern crate nix;
    use super::SeccompConfig;
    use super::SeccompJail;

    #[test]
    fn return_errno() {
        let mut config = match SeccompConfig::new("SCMP_ACT_ALLOW") {
            Ok(c) => c,
            Err(_) => {
                assert!(false);
                return;
            }
        };
        assert!(config
            .add_rule(
                "getuid",
                "SCMP_ACT_ERRNO",
                Some(0),
                Some(0),
                None,
                Some("SCMP_CMP_GE")
            )
            .is_ok());
        let jail = match SeccompJail::new(&config) {
            Ok(j) => j,
            Err(e) => {
                println!("{:?}", e);
                assert!(false);
                return;
            }
        };

        let old_uid = nix::unistd::getuid();
        assert!(jail.enter().is_ok());
        // Now uid will be a negative error code.
        assert!(nix::unistd::getuid() != old_uid);
    }

    #[test]
    fn blacklist_errno() {
        let mut config = match SeccompConfig::new("SCMP_ACT_ERRNO") {
            Ok(c) => c,
            Err(_) => {
                assert!(false);
                return;
            }
        };
        assert!(config
            .add_rule("getuid", "SCMP_ACT_ALLOW", None, None, None, None)
            .is_ok());
        assert!(config
            .add_rule("futex", "SCMP_ACT_ALLOW", None, None, None, None)
            .is_ok());
        assert!(config
            .add_rule("exit", "SCMP_ACT_ALLOW", None, None, None, None)
            .is_ok());
        assert!(config
            .add_rule("exit_group", "SCMP_ACT_ALLOW", None, None, None, None)
            .is_ok());
        assert!(config
            .add_rule("rt_sigreturn", "SCMP_ACT_ALLOW", None, None, None, None)
            .is_ok());
        let jail = match SeccompJail::new(&config) {
            Ok(j) => j,
            Err(e) => {
                println!("{:?} {:?}", e, unsafe { *libc::__errno_location() });
                assert!(false);
                return;
            }
        };

        let old_uid = nix::unistd::getuid();
        let old_euid = nix::unistd::geteuid();
        assert!(jail.enter().is_ok());
        // Getuid should still work.
        assert!(nix::unistd::getuid() == old_uid);
        // But geteuid and others should not
        assert!(nix::unistd::geteuid() != old_euid);
    }
}
