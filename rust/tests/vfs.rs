//! The virtual-filesystem list (docs/traversal.md, Mounts). The numbers are
//! compared with two independent tables (libc, linux-raw-sys) so a typo in
//! the implementation's own copy cannot pass.

use ext::vfs::is_virtual;

#[test]
fn listed_filesystems_are_virtual() {
    // (name in docs/traversal.md, magic from libc or linux-raw-sys)
    let table: [(&str, u32); 14] = [
        ("proc", libc::PROC_SUPER_MAGIC as u32),
        ("sysfs", libc::SYSFS_MAGIC as u32),
        ("tmpfs and devtmpfs", libc::TMPFS_MAGIC as u32),
        ("devpts", libc::DEVPTS_SUPER_MAGIC as u32),
        ("cgroup", libc::CGROUP_SUPER_MAGIC as u32),
        ("cgroup2", libc::CGROUP2_SUPER_MAGIC as u32),
        ("debugfs", libc::DEBUGFS_MAGIC as u32),
        ("tracefs", libc::TRACEFS_MAGIC as u32),
        ("securityfs", libc::SECURITYFS_MAGIC as u32),
        ("bpf", libc::BPF_FS_MAGIC as u32),
        ("hugetlbfs", libc::HUGETLBFS_MAGIC as u32),
        ("autofs", libc::AUTOFS_SUPER_MAGIC as u32),
        ("ramfs", linux_raw_sys::general::RAMFS_MAGIC),
        ("pstore", linux_raw_sys::general::PSTOREFS_MAGIC),
    ];
    for (name, magic) in table {
        assert!(is_virtual(magic), "{name} ({magic:#x}) must be virtual");
    }
    assert!(
        is_virtual(linux_raw_sys::general::BINFMTFS_MAGIC),
        "binfmt_misc"
    );
    assert!(
        is_virtual(linux_raw_sys::general::EFIVARFS_MAGIC),
        "efivarfs"
    );
}

// configfs, fusectl and mqueue are in neither table; the values are the
// kernel's (`stat -f -c %t` on a mount of each prints them).
#[test]
fn kernel_internal_magics_are_virtual() {
    for (name, magic) in [
        ("configfs", 0x6265_6570_u32),
        ("fusectl", 0x6573_5543),
        ("mqueue", 0x1980_0202),
    ] {
        assert!(is_virtual(magic), "{name}");
    }
}

#[test]
fn storage_filesystems_are_not_virtual() {
    for (name, magic) in [
        ("ext4", 0xEF53_u32),
        ("btrfs", 0x9123_683E),
        ("xfs", 0x5846_5342),
        ("nfs", 0x6969),
        ("vfat", 0x4d44),
        ("overlayfs", 0x794c_7630),
        ("zfs", 0x2fc1_2fc1),
        ("fuse", 0x6573_5546),
        ("squashfs", 0x7371_7368),
        ("f2fs", 0xF2F5_2010),
    ] {
        assert!(!is_virtual(magic), "{name} holds real files");
    }
}
