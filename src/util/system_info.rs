use std::sync::{Mutex, Once};
use sysinfo::{System};

pub struct SingletonSystemInfo {
    inner: Mutex<Option<System>>,
}

impl SingletonSystemInfo {
    pub fn instance() -> &'static SingletonSystemInfo {
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

    pub fn get_system(&self) -> std::sync::MutexGuard<'_, Option<System>> {
        self.inner.lock().expect("Failed to lock the singleton mutex")
    }
}
