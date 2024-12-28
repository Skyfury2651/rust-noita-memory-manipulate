mod util;
use sysinfo::Pid;
use util::system_info::SingletonSystemInfo;
use std::io::Error;
use std::mem::size_of;
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx, WriteProcessMemory};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::{DWORD, LPCVOID, LPVOID};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winnt::{HANDLE, PROCESS_VM_WRITE, PROCESS_VM_OPERATION};
use std::{ptr, thread, time};

// TODO:: Check memory usage of continue writing process
// TODO:: Get data from input instead hard code


fn main() {
    println!("Welcome ahihi");
    check_system_info();
    let process = find_noita_process().expect("No process found");

    // Location where seed using => Should be detected by code
    // Temporary using Cheat Engine to find location address of seed.
    let seed_address = 0x01202FE4; 


    let target_address = 1705961830;

    read_value_from_address(process.as_u32(), seed_address);
    lock_memory_value(process.as_u32(), seed_address, target_address);
    println!("Found noita.exe");
}

fn lock_memory_value(pid: u32, address: usize, value: i32) {
    unsafe {
        // Open the process
        let process: HANDLE = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
        if process.is_null() {
            eprintln!("Failed to open process.");
            return;
        }

        loop {
            // Write the value to the memory address
            let success = WriteProcessMemory(
                process,
                address as *mut _,
                &value as *const _ as *const _,
                std::mem::size_of::<i32>(),
                std::ptr::null_mut(),
            );

            if success == 0 {
                eprintln!("Failed to write to memory.");
                break;
            }

            // Add a delay to avoid CPU overuse
            thread::sleep(time::Duration::from_millis(50));
        }

        CloseHandle(process);
    }
}

fn check_system_info () {
    let singleton = SingletonSystemInfo::instance();
    {
        let mut system = singleton.get_system();
        if let Some(ref mut sys) = *system {
            sys.refresh_all();
            println!("Available memory: {} KB", sys.available_memory());
            println!("CPU count: {}", sys.cpus().len());
        }
    }
}

fn find_noita_process() -> Option<Pid> {
    let singleton = SingletonSystemInfo::instance();

    let mut guard = singleton.get_system();
    let s = guard.as_mut().expect("No process");
    
    let process_name = "noita.exe";
    println!("{:?}", process_name);

    for (pid, process) in s.processes() {
        let p1: Option<&str> = process.name().to_str();

        match p1 {
            Some(name) if name == process_name => {
                println!("{} has been found!", process_name);
                println!("PID is -> {}", pid);
                return Some(*pid);
            }
            _ => {
                // println!("{:?}", p1);
                // println!("Not found any process");
            }
        }
    }

    None
}

fn read_value_from_address(target_pid: u32, address: usize) -> Option<i32> {
    unsafe {
        // Open the target process
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, target_pid);
        if handle.is_null() {
            eprintln!("Failed to open process.");
            return None;
        }

        // Read the value at the given address
        let mut value: i32 = 0;
        let mut bytes_read: SIZE_T = 0;

        if ReadProcessMemory(
            handle,
            address as LPCVOID,
            &mut value as *mut i32 as LPVOID,
            size_of::<i32>(),
            &mut bytes_read,
        ) != 0 && bytes_read == size_of::<i32>() as SIZE_T
        {
            CloseHandle(handle);
            println!("{:?}", value);
            return Some(value);
        } else {
            eprintln!("Failed to read memory at address: {:X}", address);
        }

        CloseHandle(handle);
        None
    }
}

// TODO:: Improve 2 below function so don't have to use loop 
fn _write_to_memory(pid: u32, address: usize, value: i32) -> Result<(), String> {
    unsafe {
        // Open the process
        let process: HANDLE = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
        if process.is_null() {
            return Err(format!("Failed to open process: {}", Error::last_os_error()));
        }

        // Write the value to the memory address
        let success = WriteProcessMemory(
            process,
            address as *mut c_void,
            &value as *const i32 as *const c_void,
            std::mem::size_of::<i32>(),
            ptr::null_mut(),
        );

        if success == 0 {
            return Err(format!(
                "Failed to write to process memory: {}",
                Error::last_os_error()
            ));
        }

        Ok(())
    }
}

fn _find_seed_location(target_pid: DWORD) -> Option<usize> {
    // Replace this with the PID of the target process (e.g., Noita)
    // let target_pid: DWORD = 1234;

    unsafe {
        // Open the target process with read permissions
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, target_pid);
        if handle.is_null() {
            eprintln!("Failed to open process.");
            return None;
        }

        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        while VirtualQueryEx(
            handle,
            address as LPCVOID,
            &mut mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            if mbi.State == winapi::um::winnt::MEM_COMMIT
                && mbi.Protect == winapi::um::winnt::PAGE_READWRITE
            {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read: SIZE_T = 0;

                if ReadProcessMemory(
                    handle,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    &mut bytes_read,
                ) != 0
                {
                    // Scan the buffer for the value
                    let seed: i32 = 1684927956; // Replace with the seed you're looking for
                    // TODO:: taking value

                    for chunk in buffer.chunks_exact(size_of::<i32>()) {
                        let value = i32::from_ne_bytes(chunk.try_into().unwrap());
                        if value == seed {
                            println!("Found seed at address: {:X}", address);
                            return Some(address);
                        }
                        address += size_of::<i32>();
                    }
                }
            }
            address += mbi.RegionSize;
        }

        CloseHandle(handle);
        None
    }
}