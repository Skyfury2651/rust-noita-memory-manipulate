mod util;
use sysinfo::Pid;
use util::system_info::SingletonSystemInfo;

use std::ptr;
use std::mem::size_of;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::{DWORD, LPCVOID};
use winapi::shared::basetsd::SIZE_T;

fn main() {
    println!("Welcome ahihi");
    check_system_info();
    let process = find_noita_process().expect("No process found");
    let seed_address = find_seed_location(process.as_u32()).expect("Not found seed address");
    print_seed_address(seed_address);
    println!("Found noita.exe");
}

fn print_seed_address(addr: usize) {
    println!("Start looking for value address : {}", addr);
    let ptr: *const i32 = addr as *const i32;

    unsafe {
        println!("Dereference the pointer");
        // Dereference the pointer

        if !ptr.is_null() {
            println!("ptr is not null");
            // Dereference the pointer only if it's not null
            let value = *ptr;
            println!("Value at address {:x} is {}", addr, value);
        } else {
            println!("Pointer is null!");
        }
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

    return None;
}

fn find_seed_location(target_pid: DWORD) -> Option<usize> {
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
        return None;
    }
}