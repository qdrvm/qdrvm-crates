use crate::engine::PVMEngine;
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
) -> *mut PVMModule {
    if engine_ptr.is_null() || blob_ptr.is_null() {
        return ptr::null_mut();
    }

    let engine_ref = &(*engine_ptr).engine;
    let blob_slice = slice::from_raw_parts(blob_ptr, blob_size as usize);

    match ProgramBlob::parse(blob_slice.into()) {
        Ok(blob) => match Module::from_blob(engine_ref, &Default::default(), blob) {
            Ok(module) => {
                let module_box = Box::new(PVMModule { module: module });
                Box::into_raw(module_box)
            }
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Frees memory occupied by the module
#[no_mangle]
pub unsafe extern "C" fn pvm_module_free(module: *mut PVMModule) {
    if !module.is_null() {
        drop(Box::from_raw(module));
    }
}

/// Finds program entry point by function name
#[no_mangle]
pub unsafe extern "C" fn pvm_module_find_entry_point(
    module_ptr: *const PVMModule,
    name_ptr: *const u8,
    name_len: c_ulong,
    pc_out: *mut u32,
) -> bool {
    if module_ptr.is_null() || name_ptr.is_null() || pc_out.is_null() {
        return false;
    }

    let module_ref = &(*module_ptr).module;
    let name = std::str::from_utf8_unchecked(slice::from_raw_parts(name_ptr, name_len as usize));

    match module_ref.exports().find(|export| export == name) {
        Some(export) => {
            *pc_out = export.program_counter().0;
            true
        }
        None => false,
    }
}
