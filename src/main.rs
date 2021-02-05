#[cfg(windows)]
use process_memory::{DataMember, Memory, TryIntoProcessHandle};
use std::{
    io::{self, Write},
    mem::size_of,
    net::{Shutdown, TcpListener},
};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

#[cfg(not(windows))]
fn main() {
    println!("TERA only work on Windows. If you succeded to run it on linux, please contact me :)")
}

#[cfg(windows)]
#[must_use] pub fn get_pid(process_name: &str) -> process_memory::Pid {
    fn utf8_to_string(bytes: &[i8]) -> String {
        use std::ffi::CStr;
        unsafe {
            CStr::from_ptr(bytes.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    }
    let mut entry = winapi::um::tlhelp32::PROCESSENTRY32 {
        dwSize: std::mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; winapi::shared::minwindef::MAX_PATH],
    };
    let snapshot: winapi::um::winnt::HANDLE;
    unsafe {
        snapshot = winapi::um::tlhelp32::CreateToolhelp32Snapshot(
            winapi::um::tlhelp32::TH32CS_SNAPPROCESS,
            0,
        );
        if winapi::um::tlhelp32::Process32First(snapshot, &mut entry)
            == winapi::shared::minwindef::TRUE
        {
            while winapi::um::tlhelp32::Process32Next(snapshot, &mut entry)
                == winapi::shared::minwindef::TRUE
            {
                if utf8_to_string(&entry.szExeFile) == process_name {
                    return entry.th32ProcessID;
                }
            }
        }
    }
    0
}

fn check_value(data: &mut DataMember<u8>, offset: usize, value: u8) -> Result<(), ()> {
    data.set_offset(vec![offset]);
    match data.read() {
        Ok(result) => {
            if result == value {
                return Ok(());
            }
            Err(())
        }
        Err(_) => Err(()),
    }
}

fn check_pattern(
    process_handle: &mut process_memory::ProcessHandle,
    offset: usize,
) -> Result<usize, ()> {
    let mut data = DataMember::<u8>::new(*process_handle);
    check_value(&mut data, offset - 36, 0x50)?;
    check_value(&mut data, offset - 35, 0x11)?;
    check_value(&mut data, offset - 31, 0x7F)?;
    check_value(&mut data, offset - 23, 0x80)?;
    Ok(offset)
}

fn find_camera(process_handle: &mut process_memory::ProcessHandle) -> usize {
    // Camera address is never below 0x40
    let min = 0x3FF_FFFF_FFFF;
    let mut current = min;
    loop {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        unsafe {
            winapi::um::memoryapi::VirtualQueryEx(
                process_handle.0,
                current as winapi::um::winnt::PVOID,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>() as winapi::shared::basetsd::SIZE_T,
            );
        }
        if (info.Type & winapi::um::winnt::MEM_PRIVATE != 0)
            && (info.State == MEM_COMMIT)
            && (info.Protect == winapi::um::winnt::PAGE_READWRITE)
        {
            // Camera address end with 0x24. So we start at 0x24 and increase by 0x100 at each tries
            current += 0x24;
            while current < info.BaseAddress as usize + info.RegionSize as usize {
                if let Ok(offset) = check_pattern(process_handle, current) {
                    return offset;
                } else {
                    current += 0x100;
                }
            }
        }
        current = info.BaseAddress as usize + info.RegionSize as usize;
    }
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    let mut process_handle = get_pid("TERA.exe").try_into_process_handle().unwrap();
    let offset = find_camera(&mut process_handle);
    println!("Camera offset: {:X}", offset);
    let listener = TcpListener::bind("127.0.0.1:11000").expect("Failed to open socket");
    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                socket.set_nodelay(true).unwrap();
                let mut camera_angle = DataMember::<i16>::new(process_handle);
                camera_angle.set_offset(vec![offset]);
                socket
                    .write_all(&camera_angle.read()?.to_be_bytes())
                    .unwrap();
                socket
                    .shutdown(Shutdown::Both)
                    .expect("shutdown call failed");
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("IO error: {}", e),
        }
    }
    Ok(())
}
