use std::ffi::c_void;

/// Callback type for handling external calls with 3 parameters
#[repr(C)]
pub struct ExternalCallCallback3 {
    pub cb: unsafe extern "C" fn(arg_1: u32, arg_2: u32, arg_3: u32) -> u32,
    pub arg: *mut c_void,
}

unsafe impl Send for ExternalCallCallback3 {}
unsafe impl Sync for ExternalCallCallback3 {}
impl Copy for ExternalCallCallback3 {}
impl Clone for ExternalCallCallback3 {
    fn clone(&self) -> Self {
        ExternalCallCallback3 {
            cb: self.cb.clone(),
            arg: self.arg.clone(),
        }
    }
}

/// Callback type for handling external calls with no parameters
#[repr(C)]
pub struct ExternalCallCallback0 {
    pub cb: unsafe extern "C" fn() -> u32,
    pub arg: *mut c_void,
}

unsafe impl Send for ExternalCallCallback0 {}
unsafe impl Sync for ExternalCallCallback0 {}
impl Copy for ExternalCallCallback0 {}
impl Clone for ExternalCallCallback0 {
    fn clone(&self) -> Self {
        ExternalCallCallback0 {
            cb: self.cb.clone(),
            arg: self.arg.clone(),
        }
    }
}

/// Callback type for handling external calls with 1 parameter
#[repr(C)]
pub struct ExternalCallCallback1 {
    pub cb: unsafe extern "C" fn(arg_1: u32) -> u32,
    pub arg: *mut c_void,
}

unsafe impl Send for ExternalCallCallback1 {}
unsafe impl Sync for ExternalCallCallback1 {}
impl Copy for ExternalCallCallback1 {}
impl Clone for ExternalCallCallback1 {
    fn clone(&self) -> Self {
        ExternalCallCallback1 {
            cb: self.cb.clone(),
            arg: self.arg.clone(),
        }
    }
}

/// Callback type for handling external calls with 2 parameters
#[repr(C)]
pub struct ExternalCallCallback2 {
    pub cb: unsafe extern "C" fn(arg_1: u32, arg_2: u32) -> u32,
    pub arg: *mut c_void,
}

unsafe impl Send for ExternalCallCallback2 {}
unsafe impl Sync for ExternalCallCallback2 {}
impl Copy for ExternalCallCallback2 {}
impl Clone for ExternalCallCallback2 {
    fn clone(&self) -> Self {
        ExternalCallCallback2 {
            cb: self.cb.clone(),
            arg: self.arg.clone(),
        }
    }
}
