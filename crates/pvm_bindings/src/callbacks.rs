use std::ffi::c_void;
use std::os::raw::c_char;

/// Log level for debug messages
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PVMLogLevel {
    /// Error messages
    Error = 0,
    /// Warning messages
    Warning = 1,
    /// Informational messages
    Info = 2,
    /// Trace/debug messages
    Trace = 3,
}

/// Logger function callback type
#[repr(C)]
pub struct PVMLoggerCallback {
    pub cb: Option<unsafe extern "C" fn(level: PVMLogLevel, message: *const c_char)>,
    pub arg: *mut c_void,
}

impl Clone for PVMLoggerCallback {
    fn clone(&self) -> Self {
        PVMLoggerCallback {
            cb: self.cb,
            arg: self.arg,
        }
    }
}

impl Copy for PVMLoggerCallback {}

// Helper function to log messages
pub unsafe fn log_message(logger: Option<&PVMLoggerCallback>, level: PVMLogLevel, message: &str) {
    if let Some(logger) = logger {
        if let Some(cb) = logger.cb {
            let c_message = std::ffi::CString::new(message).unwrap_or_else(|_| {
                std::ffi::CString::new("Failed to create error message").unwrap()
            });
            cb(level, c_message.as_ptr());
        }
    }
}

/// Callback type for handling external calls with 3 parameters
#[repr(C)]
pub struct ExternalCallCallback3 {
    pub cb: unsafe extern "C" fn(arg_1: u32, arg_2: u32, arg_3: u32) -> u32,
    pub arg: *mut c_void,
}

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

impl Copy for ExternalCallCallback2 {}
impl Clone for ExternalCallCallback2 {
    fn clone(&self) -> Self {
        ExternalCallCallback2 {
            cb: self.cb.clone(),
            arg: self.arg.clone(),
        }
    }
}
