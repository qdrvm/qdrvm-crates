use crate::linker::PVMLinker;
use crate::log_message;
use crate::module::PVMModule;
use crate::PVMLogLevel;
use crate::PVMLoggerCallback;
use polkavm::{CallError, Instance};
use std::os::raw::c_ulong;
use std::ptr;
use std::slice;

/// Structure representing a PolkaVM instance
#[repr(C)]
pub struct PVMInstance {
    pub(crate) instance: Instance,
}

/// Creates an instance from a module using a linker
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_new(
    module_ptr: *mut PVMModule,
    linker_ptr: *mut PVMLinker,
    logger: *const PVMLoggerCallback,
) -> *mut PVMInstance {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if module_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Module pointer is null");
        return ptr::null_mut();
    }

    if linker_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Linker pointer is null");
        return ptr::null_mut();
    }

    let module_ref = &mut *module_ptr;
    let linker_ref = &mut *linker_ptr;

    match linker_ref.linker.instantiate_pre(&module_ref.module) {
        Ok(instance_pre) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                "Instance pre-instantiation successful",
            );
            match instance_pre.instantiate() {
                Ok(instance) => {
                    log_message(
                        logger_ref,
                        PVMLogLevel::Info,
                        "Instance created successfully",
                    );
                    let instance_box = Box::new(PVMInstance { instance: instance });
                    Box::into_raw(instance_box)
                }
                Err(err) => {
                    log_message(
                        logger_ref,
                        PVMLogLevel::Error,
                        &format!("Failed to instantiate instance: {}", err),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Failed to pre-instantiate instance: {}", err),
            );
            ptr::null_mut()
        }
    }
}

/// Frees memory occupied by the instance
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_free(
    instance: *mut PVMInstance,
    logger: *const PVMLoggerCallback,
) {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if instance.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Warning,
            "Attempted to free null instance pointer",
        );
        return;
    }

    log_message(logger_ref, PVMLogLevel::Info, "Freeing instance");
    drop(Box::from_raw(instance));
}

/// Writes data to the virtual machine instance memory
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_write_memory(
    instance_ptr: *mut PVMInstance,
    address: u32,
    data: *const u8,
    size: usize,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if instance_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Instance pointer is null");
        return false;
    }

    if data.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Data pointer is null");
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let data_slice = slice::from_raw_parts(data, size);

    match instance_ref.instance.write_memory(address, data_slice) {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!(
                    "Successfully wrote {} bytes to memory at address {:#x}",
                    size, address
                ),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!(
                    "Failed to write to memory at address {:#x}: {}",
                    address, err
                ),
            );
            false
        }
    }
}

/// Reads data from the virtual machine instance memory
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_read_memory(
    instance_ptr: *mut PVMInstance,
    address: u32,
    data: *mut u8,
    length: u32,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if instance_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Instance pointer is null");
        return false;
    }

    if data.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Data pointer is null");
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    match instance_ref.instance.read_memory(address, length) {
        Ok(buffer) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!(
                    "Successfully read {} bytes from memory at address {:#x}",
                    length, address
                ),
            );
            // Copy data to output buffer
            ptr::copy_nonoverlapping(buffer.as_ptr(), data, length as usize);
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!(
                    "Failed to read from memory at address {:#x}: {}",
                    address, err
                ),
            );
            false
        }
    }
}

/// Reads data from the virtual machine instance memory into the provided buffer
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_read_memory_into(
    instance_ptr: *mut PVMInstance,
    address: u32,
    data: *mut u8,
    size: usize,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if instance_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Instance pointer is null");
        return false;
    }

    if data.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Data pointer is null");
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let data_slice = slice::from_raw_parts_mut(data, size);

    match instance_ref.instance.read_memory_into(address, data_slice) {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!(
                    "Successfully read {} bytes from memory into buffer at address {:#x}",
                    size, address
                ),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!(
                    "Failed to read from memory into buffer at address {:#x}: {}",
                    address, err
                ),
            );
            false
        }
    }
}

/// Calls a function in the virtual machine with return value
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_call_function_32(
    instance_ptr: *mut PVMInstance,
    name: *const u8,
    name_len: c_ulong,
    args: *const u32,
    args_count: u32,
    result_out: *mut u32,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if instance_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Instance pointer is null");
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

    if result_out.is_null() {
        log_message(
            logger_ref,
            PVMLogLevel::Error,
            "Result output pointer is null",
        );
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    let args_slice = if !args.is_null() {
        slice::from_raw_parts(args, args_count as usize)
    } else {
        &[]
    };

    log_message(
        logger_ref,
        PVMLogLevel::Info,
        &format!(
            "Calling function '{}' with {} arguments",
            name_str, args_count
        ),
    );

    let result = match args_slice.len() {
        0 => instance_ref
            .instance
            .call_typed_and_get_result::<u32, ()>(&mut (), name_str, ()),
        2 => instance_ref
            .instance
            .call_typed_and_get_result::<u32, (u32, u32)>(
                &mut (),
                name_str,
                (args_slice[0], args_slice[1]),
            ),
        3 => instance_ref
            .instance
            .call_typed_and_get_result::<u32, (u32, u32, u32)>(
                &mut (),
                name_str,
                (args_slice[0], args_slice[1], args_slice[2]),
            ),
        4 => instance_ref
            .instance
            .call_typed_and_get_result::<u32, (u32, u32, u32, u32)>(
                &mut (),
                name_str,
                (args_slice[0], args_slice[1], args_slice[2], args_slice[3]),
            ),
        5 => instance_ref
            .instance
            .call_typed_and_get_result::<u32, (u32, u32, u32, u32, u32)>(
                &mut (),
                name_str,
                (
                    args_slice[0],
                    args_slice[1],
                    args_slice[2],
                    args_slice[3],
                    args_slice[4],
                ),
            ),
        6 => instance_ref
            .instance
            .call_typed_and_get_result::<u32, (u32, u32, u32, u32, u32, u32)>(
                &mut (),
                name_str,
                (
                    args_slice[0],
                    args_slice[1],
                    args_slice[2],
                    args_slice[3],
                    args_slice[4],
                    args_slice[5],
                ),
            ),
        _ => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!(
                    "Invalid argument count for function '{}': {}",
                    name_str,
                    args_slice.len()
                ),
            );
            Err(CallError::Error("Invalid input".into()))
        }
    };

    match result {
        Ok(result) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Function '{}' returned: {}", name_str, result),
            );
            *result_out = result;
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Function '{}' call failed: {:?}", name_str, err),
            );
            false
        }
    }
}

/// Calls a typed function in the virtual machine without returning a result
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_call_no_result_32(
    instance_ptr: *mut PVMInstance,
    name: *const u8,
    name_len: c_ulong,
    args: *const u32,
    args_count: u32,
    logger: *const PVMLoggerCallback,
) -> bool {
    let logger_ref = if !logger.is_null() {
        Some(&*logger)
    } else {
        None
    };

    if instance_ptr.is_null() {
        log_message(logger_ref, PVMLogLevel::Error, "Instance pointer is null");
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

    let instance_ref = &mut *instance_ptr;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    let args_slice = if !args.is_null() {
        slice::from_raw_parts(args, args_count as usize)
    } else {
        &[]
    };

    log_message(
        logger_ref,
        PVMLogLevel::Info,
        &format!(
            "Calling function '{}' with {} arguments (no result)",
            name_str, args_count
        ),
    );

    let result = match args_slice.len() {
        0 => instance_ref.instance.call_typed(&mut (), name_str, ()),
        2 => instance_ref
            .instance
            .call_typed(&mut (), name_str, (args_slice[0], args_slice[1])),
        3 => instance_ref.instance.call_typed(
            &mut (),
            name_str,
            (args_slice[0], args_slice[1], args_slice[2]),
        ),
        4 => instance_ref.instance.call_typed(
            &mut (),
            name_str,
            (args_slice[0], args_slice[1], args_slice[2], args_slice[3]),
        ),
        5 => instance_ref.instance.call_typed(
            &mut (),
            name_str,
            (
                args_slice[0],
                args_slice[1],
                args_slice[2],
                args_slice[3],
                args_slice[4],
            ),
        ),
        6 => instance_ref.instance.call_typed(
            &mut (),
            name_str,
            (
                args_slice[0],
                args_slice[1],
                args_slice[2],
                args_slice[3],
                args_slice[4],
                args_slice[5],
            ),
        ),
        _ => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!(
                    "Invalid argument count for function '{}': {}",
                    name_str,
                    args_slice.len()
                ),
            );
            Err(CallError::Error("Invalid input".into()))
        }
    };

    match result {
        Ok(_) => {
            log_message(
                logger_ref,
                PVMLogLevel::Info,
                &format!("Function '{}' call succeeded", name_str),
            );
            true
        }
        Err(err) => {
            log_message(
                logger_ref,
                PVMLogLevel::Error,
                &format!("Function '{}' call failed: {:?}", name_str, err),
            );
            false
        }
    }
}
