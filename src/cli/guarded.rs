use zeroize::Zeroize;

const MAX_LEN: usize = 128;

pub struct GuardedString {
    pub(super) inner: String,
    locked: bool,
}

impl GuardedString {
    pub(super) fn new() -> Self {
        let inner = String::with_capacity(MAX_LEN);
        let locked = mem_lock(inner.as_ptr(), inner.capacity());
        Self { inner, locked }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl std::ops::Deref for GuardedString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.inner
    }
}

impl PartialEq for GuardedString {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Drop for GuardedString {
    fn drop(&mut self) {
        self.inner.zeroize();
        if self.locked {
            mem_unlock(self.inner.as_ptr(), self.inner.capacity());
        }
    }
}

#[cfg(unix)]
fn mem_lock(ptr: *const u8, len: usize) -> bool {
    unsafe extern "C" {
        fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    }
    if len == 0 {
        return false;
    }
    unsafe { mlock(ptr.cast(), len) == 0 }
}

#[cfg(unix)]
fn mem_unlock(ptr: *const u8, len: usize) {
    unsafe extern "C" {
        fn munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    }
    if len > 0 {
        unsafe {
            munlock(ptr.cast(), len);
        }
    }
}

#[cfg(windows)]
fn mem_lock(ptr: *const u8, len: usize) -> bool {
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn VirtualLock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
    }
    if len == 0 {
        return false;
    }
    unsafe { VirtualLock(ptr.cast(), len) != 0 }
}

#[cfg(windows)]
fn mem_unlock(ptr: *const u8, len: usize) {
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn VirtualUnlock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
    }
    if len > 0 {
        unsafe {
            VirtualUnlock(ptr.cast(), len);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn mem_lock(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
fn mem_unlock(_ptr: *const u8, _len: usize) {}
