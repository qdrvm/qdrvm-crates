use crate::callbacks::{
    ExternalCallCallback0, ExternalCallCallback1, ExternalCallCallback2, ExternalCallCallback3,
};
use crate::log_message;
use crate::PVMLogLevel;
use crate::PVMLoggerCallback;
use polkavm::Linker;
use std::os::raw::c_ulong;
use std::slice;

/// Structure representing a PolkaVM linker
#[repr(C)]
pub struct PVMLinker {
    pub(crate) linker: Linker,
}

/// Creates a new linker
#[no_mangle]
pub unsafe extern "C" fn pvm_linker_new(logger: *const PVMLoggerCallback) -> *mut PVMLinker {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    log_message(logger_ref, PVMLogLevel::Info, "Creating new linker");
    let linker = Box::new(PVMLinker {
        linker: Linker::new(),
    });
    Box::into_raw(linker)
}

/// Frees memory occupied by the linker
#[no_mangle]
pub unsafe extern "C" fn pvm_linker_free(linker: *mut PVMLinker, logger: *const PVMLoggerCallback) {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if linker.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Warning,
            "Attempted to free null linker pointer",
        );
        return;
    }

    log_message(logger_ref, PVMLogLevel::Info, "Freeing linker");
    drop(Box::from_raw(linker));
}

/// Defines an external function in the linker (with 3 parameters)
#[no_mangle]
pub unsafe extern "C" fn pvm_linker_define_function3(
    linker: *mut PVMLinker,
    name: *const u8,
    name_len: c_ulong,
    callback: *const ExternalCallCallback3,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if linker.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Linker pointer is null");
        return false;
    }

    if name.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Error,
            "Function name pointer is null",
        );
        return false;
    }

    let callback = if let Some(callback) = callback.as_ref() {
        callback.clone()
    } else {
        log_message(logger_ref, PVMLogLevel::Error, "Callback pointer is null");
        return false;
    };

    let linker_ref = &mut *linker;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    match linker_ref
        .linker
        .define_typed(name_str, move |arg_1, arg_2, arg_3| {
            let cb = callback.cb;
            let result = cb(arg_1, arg_2, arg_3);
            result
        }) {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Successfully defined external function: {}", name_str),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Failed to define external function '{}': {}", name_str, err),
            );
            false
        }
    }
}

/// Defines an external function in the linker (with no parameters)
#[no_mangle]
pub unsafe extern "C" fn pvm_linker_define_function0(
    linker: *mut PVMLinker,
    name: *const u8,
    name_len: c_ulong,
    callback: *const ExternalCallCallback0,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if linker.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Linker pointer is null");
        return false;
    }

    if name.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Error,
            "Function name pointer is null",
        );
        return false;
    }

    let callback = if let Some(callback) = callback.as_ref() {
        callback.clone()
    } else {
        log_message(logger_ref, PVMLogLevel::Error, "Callback pointer is null");
        return false;
    };

    let linker_ref = &mut *linker;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    match linker_ref.linker.define_typed(name_str, move || {
        let cb = callback.cb;
        let result = cb();
        result
    }) {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Successfully defined external function: {}", name_str),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Failed to define external function '{}': {}", name_str, err),
            );
            false
        }
    }
}

/// Defines an external function in the linker (with 1 parameter)
#[no_mangle]
pub unsafe extern "C" fn pvm_linker_define_function1(
    linker: *mut PVMLinker,
    name: *const u8,
    name_len: c_ulong,
    callback: *const ExternalCallCallback1,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if linker.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Linker pointer is null");
        return false;
    }

    if name.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Error,
            "Function name pointer is null",
        );
        return false;
    }

    let callback = if let Some(callback) = callback.as_ref() {
        callback.clone()
    } else {
        log_message(logger_ref, PVMLogLevel::Error, "Callback pointer is null");
        return false;
    };

    let linker_ref = &mut *linker;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    match linker_ref.linker.define_typed(name_str, move |arg_1| {
        let cb = callback.cb;
        let result = cb(arg_1);
        result
    }) {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Successfully defined external function: {}", name_str),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Failed to define external function '{}': {}", name_str, err),
            );
            false
        }
    }
}

/// Defines an external function in the linker (with 2 parameters)
#[no_mangle]
pub unsafe extern "C" fn pvm_linker_define_function2(
    linker: *mut PVMLinker,
    name: *const u8,
    name_len: c_ulong,
    callback: *const ExternalCallCallback2,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if linker.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Linker pointer is null");
        return false;
    }

    if name.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Error,
            "Function name pointer is null",
        );
        return false;
    }

    let callback = if let Some(callback) = callback.as_ref() {
        callback.clone()
    } else {
        log_message(logger_ref, PVMLogLevel::Error, "Callback pointer is null");
        return false;
    };

    let linker_ref = &mut *linker;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    match linker_ref
        .linker
        .define_typed(name_str, move |arg_1, arg_2| {
            let cb = callback.cb;
            let result = cb(arg_1, arg_2);
            result
        }) {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Successfully defined external function: {}", name_str),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Failed to define external function '{}': {}", name_str, err),
            );
            false
        }
    }
}
