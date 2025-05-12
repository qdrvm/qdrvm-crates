use crate::engine::PVMEngine;
use crate::log_message;
use crate::PVMLogLevel;
use crate::PVMLoggerCallback;
use polkavm::{Module, ProgramBlob};
use std::os::raw::c_ulong;
use std::ptr;
use std::slice;

/// Structure representing a PolkaVM module
#[repr(C)]
pub struct PVMModule {
    pub(crate) module: Module,
}

/// Creates a module from a program binary blob
#[no_mangle]
pub unsafe extern "C" fn pvm_module_from_blob(
    engine_ptr: *const PVMEngine,
    blob_ptr: *const u8,
    blob_size: c_ulong,
    logger: *const PVMLoggerCallback,
) -> *mut PVMModule {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if engine_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Engine pointer is null");
        return ptr::null_mut();
    }

    if blob_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Blob pointer is null");
        return ptr::null_mut();
    }

    let engine_ref = &(*engine_ptr).engine;
    let blob_slice = slice::from_raw_parts(blob_ptr, blob_size as usize);

    match ProgramBlob::parse(blob_slice.into()) {
        Ok(blob) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                "Program blob parsed successfully",
            );
            match Module::from_blob(engine_ref, &Default::default(), blob) {
                Ok(module) => {
                    log_message(logger_ref, PVMLogLevel::Info, "Module created successfully");
                    let module_box = Box::new(PVMModule { module: module });
                    Box::into_raw(module_box)
                }
                Err(err) => {
                    log_message(
                        logger_ref,
                        PVMLogLevel::Error,
                        &format!("Failed to create module from blob: {}", err),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Failed to parse program blob: {}", err),
            );
            ptr::null_mut()
        }
    }
}

/// Frees memory occupied by the module
#[no_mangle]
pub unsafe extern "C" fn pvm_module_free(module: *mut PVMModule, logger: *const PVMLoggerCallback) {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if module.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Warning,
            "Attempted to free null module pointer",
        );
        return;
    }

    log_message(logger_ref, PVMLogLevel::Info, "Freeing module");
    drop(Box::from_raw(module));
}

/// Finds program entry point by function name
#[no_mangle]
pub unsafe extern "C" fn pvm_module_find_entry_point(
    module_ptr: *const PVMModule,
    name_ptr: *const u8,
    name_len: c_ulong,
    pc_out: *mut u32,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if module_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Module pointer is null");
        return false;
    }

    if name_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Name pointer is null");
        return false;
    }

    if pc_out.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "PC output pointer is null");
        return false;
    }

    let module_ref = &(*module_ptr).module;
    let name = std::str::from_utf8_unchecked(slice::from_raw_parts(name_ptr, name_len as usize));

    match module_ref.exports().find(|export| export == name) {
        Some(export) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Entry point found for function: {}", name),
            );
            *pc_out = export.program_counter().0;
            true
        }
        None => {
            log_message(
                logger_ref,
                PVMLogLevel::Warning,
                &format!("Entry point not found for function: {}", name),
            );
            false
        }
    }
}
