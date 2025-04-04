use crate::linker::PVMLinker;
use crate::module::PVMModule;
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
) -> *mut PVMInstance {
    if module_ptr.is_null() || linker_ptr.is_null() {
        return ptr::null_mut();
    }

    let module_ref = &mut *module_ptr;
    let linker_ref = &mut *linker_ptr;

    match linker_ref.linker.instantiate_pre(&module_ref.module) {
        Ok(instance_pre) => match instance_pre.instantiate() {
            Ok(instance) => {
                let instance_box = Box::new(PVMInstance { instance: instance });
                Box::into_raw(instance_box)
            }
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Frees memory occupied by the instance
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_free(instance: *mut PVMInstance) {
    if !instance.is_null() {
        drop(Box::from_raw(instance));
    }
}

/// Writes data to the virtual machine instance memory
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_write_memory(
    instance_ptr: *mut PVMInstance,
    address: u32,
    data: *const u8,
    size: usize,
) -> bool {
    if instance_ptr.is_null() || data.is_null() {
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let data_slice = slice::from_raw_parts(data, size);

    match instance_ref.instance.write_memory(address, data_slice) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Reads data from the virtual machine instance memory
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_read_memory(
    instance_ptr: *mut PVMInstance,
    address: u32,
    data: *mut u8,
    length: u32,
) -> bool {
    if instance_ptr.is_null() || data.is_null() {
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    match instance_ref.instance.read_memory(address, length) {
        Ok(buffer) => {
            // Copy data to output buffer
            ptr::copy_nonoverlapping(buffer.as_ptr(), data, length as usize);
            true
        }
        Err(_) => false,
    }
}

/// Reads data from the virtual machine instance memory into the provided buffer
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_read_memory_into(
    instance_ptr: *mut PVMInstance,
    address: u32,
    data: *mut u8,
    size: usize,
) -> bool {
    if instance_ptr.is_null() || data.is_null() {
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let data_slice = slice::from_raw_parts_mut(data, size);

    match instance_ref.instance.read_memory_into(address, data_slice) {
        Ok(_) => true,
        Err(_) => false,
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
) -> bool {
    if instance_ptr.is_null() || name.is_null() || result_out.is_null() {
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    let args_slice = if !args.is_null() {
        slice::from_raw_parts(args, args_count as usize)
    } else {
        &[]
    };

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
        _ => Err(CallError::Error("Invalid input".into())),
    };

    match result {
        Ok(result) => {
            *result_out = result;
            true
        }
        Err(_) => false,
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
) -> bool {
    if instance_ptr.is_null() || name.is_null() {
        return false;
    }

    let instance_ref = &mut *instance_ptr;
    let name_str = std::str::from_utf8_unchecked(slice::from_raw_parts(name, name_len as usize));

    let args_slice = if !args.is_null() {
        slice::from_raw_parts(args, args_count as usize)
    } else {
        &[]
    };

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
        _ => Err(CallError::Error("Invalid input".into())),
    };

    result.is_ok()
}
