use std::sync::{Once, Mutex};
use sysinfo::{System};

struct SingletonSystemInfo {
    inner: Mutex<Option<System>>,
}

impl SingletonSystemInfo {
    fn instance() -> &'static SingletonSystemInfo {
        static mut INSTANCE: Option<SingletonSystemInfo> = None;
        static INIT: Once = Once::new();

        unsafe {
            INIT.call_once(|| {
                INSTANCE = Some(SingletonSystemInfo {
                    inner: Mutex::new(Some(System::new_all())),
                });
            });
            INSTANCE.as_ref().unwrap()
        }
    }

    fn get_system(&self) -> std::sync::MutexGuard<'_, Option<System>> {
        self.inner.lock().expect("Failed to lock the singleton mutex")
    }
}

fn main() {

    // Access the singleton and retrieve system information
    let singleton = SingletonSystemInfo::instance();
    let mut system_info = singleton.get_system();
    {
        let mut system = singleton.get_system();
        if let Some(ref mut sys) = *system {
            sys.refresh_all();
            println!("Available memory: {} KB", sys.available_memory());
            println!("CPU count: {}", sys.cpus().len());
        }
    }
    println!("System ended");


    // let _noita_pid: Pid = match find_noita_process() {
    //     Some(pid) => pid,
    //     None => {
    //         // panic!("No process found");
    //         return
    //     }
    // };

    // get_process_information(noita_pid);
}


// fn find_noita_process() -> Option<Pid> {
//     let s: &System = get_system_info();
    
//     let process_name = "noita.exe";
//     println!("{:?}", process_name);

//     for (pid, process) in s.processes() {
//         let p1: Option<&str> = process.name().to_str();

//         match p1 {
//             Some(name) if name == process_name => {
//                 println!("{} has been found!", process_name);
//                 println!("PID is -> {}", pid);
//                 return Some(*pid);
//             }
//             _ => {
//                 println!("{:?}", p1);
//                 // println!("Not found any process");
//             }
//         }
//     }

//     return None;
// }

// fn get_process_information(pid: Pid) {

// }