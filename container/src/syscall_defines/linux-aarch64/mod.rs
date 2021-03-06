// Generated with: cat include/uapi/asm-generic/unistd.h |
//    awk ' { print "SYS_" $2 " = " $2"," } '
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum LinuxSyscall {
    SYS_io_setup = 0,
    SYS_io_destroy = 1,
    SYS_io_submit = 2,
    SYS_io_cancel = 3,
    SYS_io_getevents = 4,
    SYS_setxattr = 5,
    SYS_lsetxattr = 6,
    SYS_fsetxattr = 7,
    SYS_getxattr = 8,
    SYS_lgetxattr = 9,
    SYS_fgetxattr = 10,
    SYS_listxattr = 11,
    SYS_llistxattr = 12,
    SYS_flistxattr = 13,
    SYS_removexattr = 14,
    SYS_lremovexattr = 15,
    SYS_fremovexattr = 16,
    SYS_getcwd = 17,
    SYS_lookup_dcookie = 18,
    SYS_eventfd2 = 19,
    SYS_epoll_create1 = 20,
    SYS_epoll_ctl = 21,
    SYS_epoll_pwait = 22,
    SYS_dup = 23,
    SYS_dup3 = 24,
    SYS_inotify_init1 = 26,
    SYS_inotify_add_watch = 27,
    SYS_inotify_rm_watch = 28,
    SYS_ioctl = 29,
    SYS_ioprio_set = 30,
    SYS_ioprio_get = 31,
    SYS_flock = 32,
    SYS_mknodat = 33,
    SYS_mkdirat = 34,
    SYS_unlinkat = 35,
    SYS_symlinkat = 36,
    SYS_linkat = 37,
    SYS_renameat = 38,
    SYS_umount2 = 39,
    SYS_mount = 40,
    SYS_pivot_root = 41,
    SYS_nfsservctl = 42,
    SYS_fallocate = 47,
    SYS_faccessat = 48,
    SYS_chdir = 49,
    SYS_fchdir = 50,
    SYS_chroot = 51,
    SYS_fchmod = 52,
    SYS_fchmodat = 53,
    SYS_fchownat = 54,
    SYS_fchown = 55,
    SYS_openat = 56,
    SYS_close = 57,
    SYS_vhangup = 58,
    SYS_pipe2 = 59,
    SYS_quotactl = 60,
    SYS_getdents64 = 61,
    SYS_read = 63,
    SYS_write = 64,
    SYS_readv = 65,
    SYS_writev = 66,
    SYS_pread64 = 67,
    SYS_pwrite64 = 68,
    SYS_preadv = 69,
    SYS_pwritev = 70,
    SYS_pselect6 = 72,
    SYS_ppoll = 73,
    SYS_signalfd4 = 74,
    SYS_vmsplice = 75,
    SYS_splice = 76,
    SYS_tee = 77,
    SYS_readlinkat = 78,
    SYS_sync = 81,
    SYS_fsync = 82,
    SYS_fdatasync = 83,
    SYS_sync_file_range = 84,
    SYS_timerfd_create = 85,
    SYS_timerfd_settime = 86,
    SYS_timerfd_gettime = 87,
    SYS_utimensat = 88,
    SYS_acct = 89,
    SYS_capget = 90,
    SYS_capset = 91,
    SYS_personality = 92,
    SYS_exit = 93,
    SYS_exit_group = 94,
    SYS_waitid = 95,
    SYS_set_tid_address = 96,
    SYS_unshare = 97,
    SYS_futex = 98,
    SYS_set_robust_list = 99,
    SYS_get_robust_list = 100,
    SYS_nanosleep = 101,
    SYS_getitimer = 102,
    SYS_setitimer = 103,
    SYS_kexec_load = 104,
    SYS_init_module = 105,
    SYS_delete_module = 106,
    SYS_timer_create = 107,
    SYS_timer_gettime = 108,
    SYS_timer_getoverrun = 109,
    SYS_timer_settime = 110,
    SYS_timer_delete = 111,
    SYS_clock_settime = 112,
    SYS_clock_gettime = 113,
    SYS_clock_getres = 114,
    SYS_clock_nanosleep = 115,
    SYS_syslog = 116,
    SYS_ptrace = 117,
    SYS_sched_setparam = 118,
    SYS_sched_setscheduler = 119,
    SYS_sched_getscheduler = 120,
    SYS_sched_getparam = 121,
    SYS_sched_setaffinity = 122,
    SYS_sched_getaffinity = 123,
    SYS_sched_yield = 124,
    SYS_sched_get_priority_max = 125,
    SYS_sched_get_priority_min = 126,
    SYS_sched_rr_get_interval = 127,
    SYS_restart_syscall = 128,
    SYS_kill = 129,
    SYS_tkill = 130,
    SYS_tgkill = 131,
    SYS_sigaltstack = 132,
    SYS_rt_sigsuspend = 133,
    SYS_rt_sigaction = 134,
    SYS_rt_sigprocmask = 135,
    SYS_rt_sigpending = 136,
    SYS_rt_sigtimedwait = 137,
    SYS_rt_sigqueueinfo = 138,
    SYS_rt_sigreturn = 139,
    SYS_setpriority = 140,
    SYS_getpriority = 141,
    SYS_reboot = 142,
    SYS_setregid = 143,
    SYS_setgid = 144,
    SYS_setreuid = 145,
    SYS_setuid = 146,
    SYS_setresuid = 147,
    SYS_getresuid = 148,
    SYS_setresgid = 149,
    SYS_getresgid = 150,
    SYS_setfsuid = 151,
    SYS_setfsgid = 152,
    SYS_times = 153,
    SYS_setpgid = 154,
    SYS_getpgid = 155,
    SYS_getsid = 156,
    SYS_setsid = 157,
    SYS_getgroups = 158,
    SYS_setgroups = 159,
    SYS_uname = 160,
    SYS_sethostname = 161,
    SYS_setdomainname = 162,
    SYS_getrlimit = 163,
    SYS_setrlimit = 164,
    SYS_getrusage = 165,
    SYS_umask = 166,
    SYS_prctl = 167,
    SYS_getcpu = 168,
    SYS_gettimeofday = 169,
    SYS_settimeofday = 170,
    SYS_adjtimex = 171,
    SYS_getpid = 172,
    SYS_getppid = 173,
    SYS_getuid = 174,
    SYS_geteuid = 175,
    SYS_getgid = 176,
    SYS_getegid = 177,
    SYS_gettid = 178,
    SYS_sysinfo = 179,
    SYS_mq_open = 180,
    SYS_mq_unlink = 181,
    SYS_mq_timedsend = 182,
    SYS_mq_timedreceive = 183,
    SYS_mq_notify = 184,
    SYS_mq_getsetattr = 185,
    SYS_msgget = 186,
    SYS_msgctl = 187,
    SYS_msgrcv = 188,
    SYS_msgsnd = 189,
    SYS_semget = 190,
    SYS_semctl = 191,
    SYS_semtimedop = 192,
    SYS_semop = 193,
    SYS_shmget = 194,
    SYS_shmctl = 195,
    SYS_shmat = 196,
    SYS_shmdt = 197,
    SYS_socket = 198,
    SYS_socketpair = 199,
    SYS_bind = 200,
    SYS_listen = 201,
    SYS_accept = 202,
    SYS_connect = 203,
    SYS_getsockname = 204,
    SYS_getpeername = 205,
    SYS_sendto = 206,
    SYS_recvfrom = 207,
    SYS_setsockopt = 208,
    SYS_getsockopt = 209,
    SYS_shutdown = 210,
    SYS_sendmsg = 211,
    SYS_recvmsg = 212,
    SYS_readahead = 213,
    SYS_brk = 214,
    SYS_munmap = 215,
    SYS_mremap = 216,
    SYS_add_key = 217,
    SYS_request_key = 218,
    SYS_keyctl = 219,
    SYS_clone = 220,
    SYS_execve = 221,
    SYS_swapon = 224,
    SYS_swapoff = 225,
    SYS_mprotect = 226,
    SYS_msync = 227,
    SYS_mlock = 228,
    SYS_munlock = 229,
    SYS_mlockall = 230,
    SYS_munlockall = 231,
    SYS_mincore = 232,
    SYS_madvise = 233,
    SYS_remap_file_pages = 234,
    SYS_mbind = 235,
    SYS_get_mempolicy = 236,
    SYS_set_mempolicy = 237,
    SYS_migrate_pages = 238,
    SYS_move_pages = 239,
    SYS_rt_tgsigqueueinfo = 240,
    SYS_perf_event_open = 241,
    SYS_accept4 = 242,
    SYS_recvmmsg = 243,
    SYS_arch_specific_syscall = 244,
    SYS_wait4 = 260,
    SYS_prlimit64 = 261,
    SYS_fanotify_init = 262,
    SYS_fanotify_mark = 263,
    SYS_name_to_handle_at = 264,
    SYS_open_by_handle_at = 265,
    SYS_clock_adjtime = 266,
    SYS_syncfs = 267,
    SYS_setns = 268,
    SYS_sendmmsg = 269,
    SYS_process_vm_readv = 270,
    SYS_process_vm_writev = 271,
    SYS_kcmp = 272,
    SYS_finit_module = 273,
    SYS_sched_setattr = 274,
    SYS_sched_getattr = 275,
    SYS_renameat2 = 276,
    SYS_seccomp = 277,
    SYS_getrandom = 278,
    SYS_memfd_create = 279,
    SYS_bpf = 280,
    SYS_execveat = 281,
    SYS_userfaultfd = 282,
    SYS_membarrier = 283,
    SYS_mlock2 = 284,
    SYS_copy_file_range = 285,
    SYS_preadv2 = 286,
    SYS_pwritev2 = 287,
    SYS_pkey_mprotect = 288,
    SYS_pkey_alloc = 289,
    SYS_pkey_free = 290,
    SYS_syscalls = 291,
    SYS_open = 1024,
    SYS_link = 1025,
    SYS_unlink = 1026,
    SYS_mknod = 1027,
    SYS_chmod = 1028,
    SYS_chown = 1029,
    SYS_mkdir = 1030,
    SYS_rmdir = 1031,
    SYS_lchown = 1032,
    SYS_access = 1033,
    SYS_rename = 1034,
    SYS_readlink = 1035,
    SYS_symlink = 1036,
    SYS_utimes = 1037,
    SYS_pipe = 1040,
    SYS_dup2 = 1041,
    SYS_epoll_create = 1042,
    SYS_inotify_init = 1043,
    SYS_eventfd = 1044,
    SYS_signalfd = 1045,
    SYS_sendfile = 1046,
    SYS_ftruncate = 1047,
    SYS_truncate = 1048,
    SYS_stat = 1049,
    SYS_lstat = 1050,
    SYS_fstat = 1051,
    SYS_fcntl = 1052,
    SYS_fadvise64 = 1053,
    SYS_newfstatat = 1054,
    SYS_fstatfs = 1055,
    SYS_statfs = 1056,
    SYS_lseek = 1057,
    SYS_mmap = 1058,
    SYS_alarm = 1059,
    SYS_getpgrp = 1060,
    SYS_pause = 1061,
    SYS_time = 1062,
    SYS_utime = 1063,
    SYS_creat = 1064,
    SYS_getdents = 1065,
    SYS_futimesat = 1066,
    SYS_select = 1067,
    SYS_poll = 1068,
    SYS_epoll_wait = 1069,
    SYS_ustat = 1070,
    SYS_vfork = 1071,
    SYS_oldwait4 = 1072,
    SYS_recv = 1073,
    SYS_send = 1074,
    SYS_bdflush = 1075,
    SYS_umount = 1076,
    SYS_uselib = 1077,
    SYS__sysctl = 1078,
    SYS_fork = 1079,
}

pub fn from_name(name: &str) -> Result<LinuxSyscall, super::Error> {
    match name {
        "io_setup" => Ok(LinuxSyscall::SYS_io_setup),
        "io_destroy" => Ok(LinuxSyscall::SYS_io_destroy),
        "io_submit" => Ok(LinuxSyscall::SYS_io_submit),
        "io_cancel" => Ok(LinuxSyscall::SYS_io_cancel),
        "io_getevents" => Ok(LinuxSyscall::SYS_io_getevents),
        "setxattr" => Ok(LinuxSyscall::SYS_setxattr),
        "lsetxattr" => Ok(LinuxSyscall::SYS_lsetxattr),
        "fsetxattr" => Ok(LinuxSyscall::SYS_fsetxattr),
        "getxattr" => Ok(LinuxSyscall::SYS_getxattr),
        "lgetxattr" => Ok(LinuxSyscall::SYS_lgetxattr),
        "fgetxattr" => Ok(LinuxSyscall::SYS_fgetxattr),
        "listxattr" => Ok(LinuxSyscall::SYS_listxattr),
        "llistxattr" => Ok(LinuxSyscall::SYS_llistxattr),
        "flistxattr" => Ok(LinuxSyscall::SYS_flistxattr),
        "removexattr" => Ok(LinuxSyscall::SYS_removexattr),
        "lremovexattr" => Ok(LinuxSyscall::SYS_lremovexattr),
        "fremovexattr" => Ok(LinuxSyscall::SYS_fremovexattr),
        "getcwd" => Ok(LinuxSyscall::SYS_getcwd),
        "lookup_dcookie" => Ok(LinuxSyscall::SYS_lookup_dcookie),
        "eventfd2" => Ok(LinuxSyscall::SYS_eventfd2),
        "epoll_create1" => Ok(LinuxSyscall::SYS_epoll_create1),
        "epoll_ctl" => Ok(LinuxSyscall::SYS_epoll_ctl),
        "epoll_pwait" => Ok(LinuxSyscall::SYS_epoll_pwait),
        "dup" => Ok(LinuxSyscall::SYS_dup),
        "dup3" => Ok(LinuxSyscall::SYS_dup3),
        "inotify_init1" => Ok(LinuxSyscall::SYS_inotify_init1),
        "inotify_add_watch" => Ok(LinuxSyscall::SYS_inotify_add_watch),
        "inotify_rm_watch" => Ok(LinuxSyscall::SYS_inotify_rm_watch),
        "ioctl" => Ok(LinuxSyscall::SYS_ioctl),
        "ioprio_set" => Ok(LinuxSyscall::SYS_ioprio_set),
        "ioprio_get" => Ok(LinuxSyscall::SYS_ioprio_get),
        "flock" => Ok(LinuxSyscall::SYS_flock),
        "mknodat" => Ok(LinuxSyscall::SYS_mknodat),
        "mkdirat" => Ok(LinuxSyscall::SYS_mkdirat),
        "unlinkat" => Ok(LinuxSyscall::SYS_unlinkat),
        "symlinkat" => Ok(LinuxSyscall::SYS_symlinkat),
        "linkat" => Ok(LinuxSyscall::SYS_linkat),
        "renameat" => Ok(LinuxSyscall::SYS_renameat),
        "umount2" => Ok(LinuxSyscall::SYS_umount2),
        "mount" => Ok(LinuxSyscall::SYS_mount),
        "pivot_root" => Ok(LinuxSyscall::SYS_pivot_root),
        "nfsservctl" => Ok(LinuxSyscall::SYS_nfsservctl),
        "fallocate" => Ok(LinuxSyscall::SYS_fallocate),
        "faccessat" => Ok(LinuxSyscall::SYS_faccessat),
        "chdir" => Ok(LinuxSyscall::SYS_chdir),
        "fchdir" => Ok(LinuxSyscall::SYS_fchdir),
        "chroot" => Ok(LinuxSyscall::SYS_chroot),
        "fchmod" => Ok(LinuxSyscall::SYS_fchmod),
        "fchmodat" => Ok(LinuxSyscall::SYS_fchmodat),
        "fchownat" => Ok(LinuxSyscall::SYS_fchownat),
        "fchown" => Ok(LinuxSyscall::SYS_fchown),
        "openat" => Ok(LinuxSyscall::SYS_openat),
        "close" => Ok(LinuxSyscall::SYS_close),
        "vhangup" => Ok(LinuxSyscall::SYS_vhangup),
        "pipe2" => Ok(LinuxSyscall::SYS_pipe2),
        "quotactl" => Ok(LinuxSyscall::SYS_quotactl),
        "getdents64" => Ok(LinuxSyscall::SYS_getdents64),
        "read" => Ok(LinuxSyscall::SYS_read),
        "write" => Ok(LinuxSyscall::SYS_write),
        "readv" => Ok(LinuxSyscall::SYS_readv),
        "writev" => Ok(LinuxSyscall::SYS_writev),
        "pread64" => Ok(LinuxSyscall::SYS_pread64),
        "pwrite64" => Ok(LinuxSyscall::SYS_pwrite64),
        "preadv" => Ok(LinuxSyscall::SYS_preadv),
        "pwritev" => Ok(LinuxSyscall::SYS_pwritev),
        "pselect6" => Ok(LinuxSyscall::SYS_pselect6),
        "ppoll" => Ok(LinuxSyscall::SYS_ppoll),
        "signalfd4" => Ok(LinuxSyscall::SYS_signalfd4),
        "vmsplice" => Ok(LinuxSyscall::SYS_vmsplice),
        "splice" => Ok(LinuxSyscall::SYS_splice),
        "tee" => Ok(LinuxSyscall::SYS_tee),
        "readlinkat" => Ok(LinuxSyscall::SYS_readlinkat),
        "sync" => Ok(LinuxSyscall::SYS_sync),
        "fsync" => Ok(LinuxSyscall::SYS_fsync),
        "fdatasync" => Ok(LinuxSyscall::SYS_fdatasync),
        "sync_file_range" => Ok(LinuxSyscall::SYS_sync_file_range),
        "timerfd_create" => Ok(LinuxSyscall::SYS_timerfd_create),
        "timerfd_settime" => Ok(LinuxSyscall::SYS_timerfd_settime),
        "timerfd_gettime" => Ok(LinuxSyscall::SYS_timerfd_gettime),
        "utimensat" => Ok(LinuxSyscall::SYS_utimensat),
        "acct" => Ok(LinuxSyscall::SYS_acct),
        "capget" => Ok(LinuxSyscall::SYS_capget),
        "capset" => Ok(LinuxSyscall::SYS_capset),
        "personality" => Ok(LinuxSyscall::SYS_personality),
        "exit" => Ok(LinuxSyscall::SYS_exit),
        "exit_group" => Ok(LinuxSyscall::SYS_exit_group),
        "waitid" => Ok(LinuxSyscall::SYS_waitid),
        "set_tid_address" => Ok(LinuxSyscall::SYS_set_tid_address),
        "unshare" => Ok(LinuxSyscall::SYS_unshare),
        "futex" => Ok(LinuxSyscall::SYS_futex),
        "set_robust_list" => Ok(LinuxSyscall::SYS_set_robust_list),
        "get_robust_list" => Ok(LinuxSyscall::SYS_get_robust_list),
        "nanosleep" => Ok(LinuxSyscall::SYS_nanosleep),
        "getitimer" => Ok(LinuxSyscall::SYS_getitimer),
        "setitimer" => Ok(LinuxSyscall::SYS_setitimer),
        "kexec_load" => Ok(LinuxSyscall::SYS_kexec_load),
        "init_module" => Ok(LinuxSyscall::SYS_init_module),
        "delete_module" => Ok(LinuxSyscall::SYS_delete_module),
        "timer_create" => Ok(LinuxSyscall::SYS_timer_create),
        "timer_gettime" => Ok(LinuxSyscall::SYS_timer_gettime),
        "timer_getoverrun" => Ok(LinuxSyscall::SYS_timer_getoverrun),
        "timer_settime" => Ok(LinuxSyscall::SYS_timer_settime),
        "timer_delete" => Ok(LinuxSyscall::SYS_timer_delete),
        "clock_settime" => Ok(LinuxSyscall::SYS_clock_settime),
        "clock_gettime" => Ok(LinuxSyscall::SYS_clock_gettime),
        "clock_getres" => Ok(LinuxSyscall::SYS_clock_getres),
        "clock_nanosleep" => Ok(LinuxSyscall::SYS_clock_nanosleep),
        "syslog" => Ok(LinuxSyscall::SYS_syslog),
        "ptrace" => Ok(LinuxSyscall::SYS_ptrace),
        "sched_setparam" => Ok(LinuxSyscall::SYS_sched_setparam),
        "sched_setscheduler" => Ok(LinuxSyscall::SYS_sched_setscheduler),
        "sched_getscheduler" => Ok(LinuxSyscall::SYS_sched_getscheduler),
        "sched_getparam" => Ok(LinuxSyscall::SYS_sched_getparam),
        "sched_setaffinity" => Ok(LinuxSyscall::SYS_sched_setaffinity),
        "sched_getaffinity" => Ok(LinuxSyscall::SYS_sched_getaffinity),
        "sched_yield" => Ok(LinuxSyscall::SYS_sched_yield),
        "sched_get_priority_max" => Ok(LinuxSyscall::SYS_sched_get_priority_max),
        "sched_get_priority_min" => Ok(LinuxSyscall::SYS_sched_get_priority_min),
        "sched_rr_get_interval" => Ok(LinuxSyscall::SYS_sched_rr_get_interval),
        "restart_syscall" => Ok(LinuxSyscall::SYS_restart_syscall),
        "kill" => Ok(LinuxSyscall::SYS_kill),
        "tkill" => Ok(LinuxSyscall::SYS_tkill),
        "tgkill" => Ok(LinuxSyscall::SYS_tgkill),
        "sigaltstack" => Ok(LinuxSyscall::SYS_sigaltstack),
        "rt_sigsuspend" => Ok(LinuxSyscall::SYS_rt_sigsuspend),
        "rt_sigaction" => Ok(LinuxSyscall::SYS_rt_sigaction),
        "rt_sigprocmask" => Ok(LinuxSyscall::SYS_rt_sigprocmask),
        "rt_sigpending" => Ok(LinuxSyscall::SYS_rt_sigpending),
        "rt_sigtimedwait" => Ok(LinuxSyscall::SYS_rt_sigtimedwait),
        "rt_sigqueueinfo" => Ok(LinuxSyscall::SYS_rt_sigqueueinfo),
        "rt_sigreturn" => Ok(LinuxSyscall::SYS_rt_sigreturn),
        "setpriority" => Ok(LinuxSyscall::SYS_setpriority),
        "getpriority" => Ok(LinuxSyscall::SYS_getpriority),
        "reboot" => Ok(LinuxSyscall::SYS_reboot),
        "setregid" => Ok(LinuxSyscall::SYS_setregid),
        "setgid" => Ok(LinuxSyscall::SYS_setgid),
        "setreuid" => Ok(LinuxSyscall::SYS_setreuid),
        "setuid" => Ok(LinuxSyscall::SYS_setuid),
        "setresuid" => Ok(LinuxSyscall::SYS_setresuid),
        "getresuid" => Ok(LinuxSyscall::SYS_getresuid),
        "setresgid" => Ok(LinuxSyscall::SYS_setresgid),
        "getresgid" => Ok(LinuxSyscall::SYS_getresgid),
        "setfsuid" => Ok(LinuxSyscall::SYS_setfsuid),
        "setfsgid" => Ok(LinuxSyscall::SYS_setfsgid),
        "times" => Ok(LinuxSyscall::SYS_times),
        "setpgid" => Ok(LinuxSyscall::SYS_setpgid),
        "getpgid" => Ok(LinuxSyscall::SYS_getpgid),
        "getsid" => Ok(LinuxSyscall::SYS_getsid),
        "setsid" => Ok(LinuxSyscall::SYS_setsid),
        "getgroups" => Ok(LinuxSyscall::SYS_getgroups),
        "setgroups" => Ok(LinuxSyscall::SYS_setgroups),
        "uname" => Ok(LinuxSyscall::SYS_uname),
        "sethostname" => Ok(LinuxSyscall::SYS_sethostname),
        "setdomainname" => Ok(LinuxSyscall::SYS_setdomainname),
        "getrlimit" => Ok(LinuxSyscall::SYS_getrlimit),
        "setrlimit" => Ok(LinuxSyscall::SYS_setrlimit),
        "getrusage" => Ok(LinuxSyscall::SYS_getrusage),
        "umask" => Ok(LinuxSyscall::SYS_umask),
        "prctl" => Ok(LinuxSyscall::SYS_prctl),
        "getcpu" => Ok(LinuxSyscall::SYS_getcpu),
        "gettimeofday" => Ok(LinuxSyscall::SYS_gettimeofday),
        "settimeofday" => Ok(LinuxSyscall::SYS_settimeofday),
        "adjtimex" => Ok(LinuxSyscall::SYS_adjtimex),
        "getpid" => Ok(LinuxSyscall::SYS_getpid),
        "getppid" => Ok(LinuxSyscall::SYS_getppid),
        "getuid" => Ok(LinuxSyscall::SYS_getuid),
        "geteuid" => Ok(LinuxSyscall::SYS_geteuid),
        "getgid" => Ok(LinuxSyscall::SYS_getgid),
        "getegid" => Ok(LinuxSyscall::SYS_getegid),
        "gettid" => Ok(LinuxSyscall::SYS_gettid),
        "sysinfo" => Ok(LinuxSyscall::SYS_sysinfo),
        "mq_open" => Ok(LinuxSyscall::SYS_mq_open),
        "mq_unlink" => Ok(LinuxSyscall::SYS_mq_unlink),
        "mq_timedsend" => Ok(LinuxSyscall::SYS_mq_timedsend),
        "mq_timedreceive" => Ok(LinuxSyscall::SYS_mq_timedreceive),
        "mq_notify" => Ok(LinuxSyscall::SYS_mq_notify),
        "mq_getsetattr" => Ok(LinuxSyscall::SYS_mq_getsetattr),
        "msgget" => Ok(LinuxSyscall::SYS_msgget),
        "msgctl" => Ok(LinuxSyscall::SYS_msgctl),
        "msgrcv" => Ok(LinuxSyscall::SYS_msgrcv),
        "msgsnd" => Ok(LinuxSyscall::SYS_msgsnd),
        "semget" => Ok(LinuxSyscall::SYS_semget),
        "semctl" => Ok(LinuxSyscall::SYS_semctl),
        "semtimedop" => Ok(LinuxSyscall::SYS_semtimedop),
        "semop" => Ok(LinuxSyscall::SYS_semop),
        "shmget" => Ok(LinuxSyscall::SYS_shmget),
        "shmctl" => Ok(LinuxSyscall::SYS_shmctl),
        "shmat" => Ok(LinuxSyscall::SYS_shmat),
        "shmdt" => Ok(LinuxSyscall::SYS_shmdt),
        "socket" => Ok(LinuxSyscall::SYS_socket),
        "socketpair" => Ok(LinuxSyscall::SYS_socketpair),
        "bind" => Ok(LinuxSyscall::SYS_bind),
        "listen" => Ok(LinuxSyscall::SYS_listen),
        "accept" => Ok(LinuxSyscall::SYS_accept),
        "connect" => Ok(LinuxSyscall::SYS_connect),
        "getsockname" => Ok(LinuxSyscall::SYS_getsockname),
        "getpeername" => Ok(LinuxSyscall::SYS_getpeername),
        "sendto" => Ok(LinuxSyscall::SYS_sendto),
        "recvfrom" => Ok(LinuxSyscall::SYS_recvfrom),
        "setsockopt" => Ok(LinuxSyscall::SYS_setsockopt),
        "getsockopt" => Ok(LinuxSyscall::SYS_getsockopt),
        "shutdown" => Ok(LinuxSyscall::SYS_shutdown),
        "sendmsg" => Ok(LinuxSyscall::SYS_sendmsg),
        "recvmsg" => Ok(LinuxSyscall::SYS_recvmsg),
        "readahead" => Ok(LinuxSyscall::SYS_readahead),
        "brk" => Ok(LinuxSyscall::SYS_brk),
        "munmap" => Ok(LinuxSyscall::SYS_munmap),
        "mremap" => Ok(LinuxSyscall::SYS_mremap),
        "add_key" => Ok(LinuxSyscall::SYS_add_key),
        "request_key" => Ok(LinuxSyscall::SYS_request_key),
        "keyctl" => Ok(LinuxSyscall::SYS_keyctl),
        "clone" => Ok(LinuxSyscall::SYS_clone),
        "execve" => Ok(LinuxSyscall::SYS_execve),
        "swapon" => Ok(LinuxSyscall::SYS_swapon),
        "swapoff" => Ok(LinuxSyscall::SYS_swapoff),
        "mprotect" => Ok(LinuxSyscall::SYS_mprotect),
        "msync" => Ok(LinuxSyscall::SYS_msync),
        "mlock" => Ok(LinuxSyscall::SYS_mlock),
        "munlock" => Ok(LinuxSyscall::SYS_munlock),
        "mlockall" => Ok(LinuxSyscall::SYS_mlockall),
        "munlockall" => Ok(LinuxSyscall::SYS_munlockall),
        "mincore" => Ok(LinuxSyscall::SYS_mincore),
        "madvise" => Ok(LinuxSyscall::SYS_madvise),
        "remap_file_pages" => Ok(LinuxSyscall::SYS_remap_file_pages),
        "mbind" => Ok(LinuxSyscall::SYS_mbind),
        "get_mempolicy" => Ok(LinuxSyscall::SYS_get_mempolicy),
        "set_mempolicy" => Ok(LinuxSyscall::SYS_set_mempolicy),
        "migrate_pages" => Ok(LinuxSyscall::SYS_migrate_pages),
        "move_pages" => Ok(LinuxSyscall::SYS_move_pages),
        "rt_tgsigqueueinfo" => Ok(LinuxSyscall::SYS_rt_tgsigqueueinfo),
        "perf_event_open" => Ok(LinuxSyscall::SYS_perf_event_open),
        "accept4" => Ok(LinuxSyscall::SYS_accept4),
        "recvmmsg" => Ok(LinuxSyscall::SYS_recvmmsg),
        "arch_specific_syscall" => Ok(LinuxSyscall::SYS_arch_specific_syscall),
        "wait4" => Ok(LinuxSyscall::SYS_wait4),
        "prlimit64" => Ok(LinuxSyscall::SYS_prlimit64),
        "fanotify_init" => Ok(LinuxSyscall::SYS_fanotify_init),
        "fanotify_mark" => Ok(LinuxSyscall::SYS_fanotify_mark),
        "name_to_handle_at" => Ok(LinuxSyscall::SYS_name_to_handle_at),
        "open_by_handle_at" => Ok(LinuxSyscall::SYS_open_by_handle_at),
        "clock_adjtime" => Ok(LinuxSyscall::SYS_clock_adjtime),
        "syncfs" => Ok(LinuxSyscall::SYS_syncfs),
        "setns" => Ok(LinuxSyscall::SYS_setns),
        "sendmmsg" => Ok(LinuxSyscall::SYS_sendmmsg),
        "process_vm_readv" => Ok(LinuxSyscall::SYS_process_vm_readv),
        "process_vm_writev" => Ok(LinuxSyscall::SYS_process_vm_writev),
        "kcmp" => Ok(LinuxSyscall::SYS_kcmp),
        "finit_module" => Ok(LinuxSyscall::SYS_finit_module),
        "sched_setattr" => Ok(LinuxSyscall::SYS_sched_setattr),
        "sched_getattr" => Ok(LinuxSyscall::SYS_sched_getattr),
        "renameat2" => Ok(LinuxSyscall::SYS_renameat2),
        "seccomp" => Ok(LinuxSyscall::SYS_seccomp),
        "getrandom" => Ok(LinuxSyscall::SYS_getrandom),
        "memfd_create" => Ok(LinuxSyscall::SYS_memfd_create),
        "bpf" => Ok(LinuxSyscall::SYS_bpf),
        "execveat" => Ok(LinuxSyscall::SYS_execveat),
        "userfaultfd" => Ok(LinuxSyscall::SYS_userfaultfd),
        "membarrier" => Ok(LinuxSyscall::SYS_membarrier),
        "mlock2" => Ok(LinuxSyscall::SYS_mlock2),
        "copy_file_range" => Ok(LinuxSyscall::SYS_copy_file_range),
        "preadv2" => Ok(LinuxSyscall::SYS_preadv2),
        "pwritev2" => Ok(LinuxSyscall::SYS_pwritev2),
        "pkey_mprotect" => Ok(LinuxSyscall::SYS_pkey_mprotect),
        "pkey_alloc" => Ok(LinuxSyscall::SYS_pkey_alloc),
        "pkey_free" => Ok(LinuxSyscall::SYS_pkey_free),
        "syscalls" => Ok(LinuxSyscall::SYS_syscalls),
        "open" => Ok(LinuxSyscall::SYS_open),
        "link" => Ok(LinuxSyscall::SYS_link),
        "unlink" => Ok(LinuxSyscall::SYS_unlink),
        "mknod" => Ok(LinuxSyscall::SYS_mknod),
        "chmod" => Ok(LinuxSyscall::SYS_chmod),
        "chown" => Ok(LinuxSyscall::SYS_chown),
        "mkdir" => Ok(LinuxSyscall::SYS_mkdir),
        "rmdir" => Ok(LinuxSyscall::SYS_rmdir),
        "lchown" => Ok(LinuxSyscall::SYS_lchown),
        "access" => Ok(LinuxSyscall::SYS_access),
        "rename" => Ok(LinuxSyscall::SYS_rename),
        "readlink" => Ok(LinuxSyscall::SYS_readlink),
        "symlink" => Ok(LinuxSyscall::SYS_symlink),
        "utimes" => Ok(LinuxSyscall::SYS_utimes),
        "pipe" => Ok(LinuxSyscall::SYS_pipe),
        "dup2" => Ok(LinuxSyscall::SYS_dup2),
        "epoll_create" => Ok(LinuxSyscall::SYS_epoll_create),
        "inotify_init" => Ok(LinuxSyscall::SYS_inotify_init),
        "eventfd" => Ok(LinuxSyscall::SYS_eventfd),
        "signalfd" => Ok(LinuxSyscall::SYS_signalfd),
        "sendfile" => Ok(LinuxSyscall::SYS_sendfile),
        "ftruncate" => Ok(LinuxSyscall::SYS_ftruncate),
        "truncate" => Ok(LinuxSyscall::SYS_truncate),
        "stat" => Ok(LinuxSyscall::SYS_stat),
        "lstat" => Ok(LinuxSyscall::SYS_lstat),
        "fstat" => Ok(LinuxSyscall::SYS_fstat),
        "fcntl" => Ok(LinuxSyscall::SYS_fcntl),
        "fadvise64" => Ok(LinuxSyscall::SYS_fadvise64),
        "newfstatat" => Ok(LinuxSyscall::SYS_newfstatat),
        "fstatfs" => Ok(LinuxSyscall::SYS_fstatfs),
        "statfs" => Ok(LinuxSyscall::SYS_statfs),
        "lseek" => Ok(LinuxSyscall::SYS_lseek),
        "mmap" => Ok(LinuxSyscall::SYS_mmap),
        "alarm" => Ok(LinuxSyscall::SYS_alarm),
        "getpgrp" => Ok(LinuxSyscall::SYS_getpgrp),
        "pause" => Ok(LinuxSyscall::SYS_pause),
        "time" => Ok(LinuxSyscall::SYS_time),
        "utime" => Ok(LinuxSyscall::SYS_utime),
        "creat" => Ok(LinuxSyscall::SYS_creat),
        "getdents" => Ok(LinuxSyscall::SYS_getdents),
        "futimesat" => Ok(LinuxSyscall::SYS_futimesat),
        "select" => Ok(LinuxSyscall::SYS_select),
        "poll" => Ok(LinuxSyscall::SYS_poll),
        "epoll_wait" => Ok(LinuxSyscall::SYS_epoll_wait),
        "ustat" => Ok(LinuxSyscall::SYS_ustat),
        "vfork" => Ok(LinuxSyscall::SYS_vfork),
        "oldwait4" => Ok(LinuxSyscall::SYS_oldwait4),
        "recv" => Ok(LinuxSyscall::SYS_recv),
        "send" => Ok(LinuxSyscall::SYS_send),
        "bdflush" => Ok(LinuxSyscall::SYS_bdflush),
        "umount" => Ok(LinuxSyscall::SYS_umount),
        "uselib" => Ok(LinuxSyscall::SYS_uselib),
        "_sysctl" => Ok(LinuxSyscall::SYS__sysctl),
        "fork" => Ok(LinuxSyscall::SYS_fork),
        _ => Err(super::Error::UnknownSyscall),
    }
}
