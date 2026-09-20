// Stack-only event naming. This fixture does not need the Rust runtime at PE entry.
use winapi::um::{
    handleapi::CloseHandle,
    processthreadsapi::GetCurrentProcessId,
    synchapi::{OpenEventW, SetEvent, WaitForSingleObject},
    winbase::WAIT_OBJECT_0,
    winnt::{EVENT_MODIFY_STATE, HANDLE, SYNCHRONIZE},
};
#[allow(dead_code)]
fn open(prefix: &[u8]) -> HANDLE {
    let mut name = [0u16; 96];
    let mut n = 0;
    for b in prefix {
        name[n] = u16::from(*b);
        n += 1;
    }
    let mut pid = unsafe { GetCurrentProcessId() };
    let mut digits = [0u16; 10];
    let mut count = 0;
    loop {
        digits[count] = 48 + (pid % 10) as u16;
        count += 1;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        name[n] = digits[count];
        n += 1;
    }
    // Borrow the terminated stack buffer; do not allocate at PE entry or DllMain.
    let Ok(name) = wincorda::NullTerminated::<wincorda::WCHAR>::try_from(&name[..=n]) else {
        return std::ptr::null_mut();
    };
    unsafe { OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, 0, name.as_ptr()) }
}
#[allow(dead_code)]
fn signal(prefix: &[u8]) {
    unsafe {
        let h = open(prefix);
        if !h.is_null() {
            SetEvent(h);
            CloseHandle(h);
        }
    }
}
#[allow(dead_code)]
fn signaled(prefix: &[u8]) -> bool {
    unsafe {
        let h = open(prefix);
        if h.is_null() {
            return false;
        }
        let value = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
        CloseHandle(h);
        value
    }
}
