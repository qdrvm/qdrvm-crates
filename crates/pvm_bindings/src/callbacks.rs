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

macro_rules! define_external_call_callback {
    ($name:ident, $($arg_name:ident: $arg_type:ty),*) => {
        /// Callback type for handling external calls
        #[repr(C)]
        pub struct $name {
            pub cb: unsafe extern "C" fn($($arg_name: $arg_type),*) -> u32,
            pub arg: *mut c_void,
        }

        impl Copy for $name {}
        impl Clone for $name {
            fn clone(&self) -> Self {
                $name {
                    cb: self.cb.clone(),
                    arg: self.arg.clone(),
                }
            }
        }
    };
}

define_external_call_callback!(ExternalCallCallback0,);
define_external_call_callback!(ExternalCallCallback1, arg_1: u32);
define_external_call_callback!(ExternalCallCallback2, arg_1: u32, arg_2: u32);
define_external_call_callback!(ExternalCallCallback3, arg_1: u32, arg_2: u32, arg_3: u32);
