//! C-bindings for PolkaVM

mod callbacks;
mod engine;
mod instance;
mod linker;
mod module;

pub use callbacks::{
    ExternalCallCallback0, ExternalCallCallback1, ExternalCallCallback2, ExternalCallCallback3,
};
pub use engine::{pvm_engine_free, pvm_engine_new, PVMEngine};
pub use instance::{
    pvm_instance_call_function_32, pvm_instance_call_no_result_32, pvm_instance_free,
    pvm_instance_new, pvm_instance_read_memory, pvm_instance_read_memory_into,
    pvm_instance_write_memory, PVMInstance,
};
pub use linker::{
    pvm_linker_define_function0, pvm_linker_define_function1, pvm_linker_define_function2,
    pvm_linker_define_function3, pvm_linker_free, pvm_linker_new, PVMLinker,
};
pub use module::{pvm_module_find_entry_point, pvm_module_free, pvm_module_from_blob, PVMModule};

/// Size of the PolkaVM program binary blob
pub const PVM_BLOB_SIZE: usize = 4096;

/// Configuration structure for the virtual machine
#[repr(C)]
pub struct PVMConfig {
    /// Memory size in bytes
    pub memory_size: u32,
    /// Allow dynamic paging
    pub allow_dynamic_paging: bool,
    /// Number of worker threads
    pub worker_count: u32,
    /// Backend type
    pub backend: u32,
    /// Sandbox type
    pub sandbox: u32,
}

/// Backend type
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PVMBackend {
    /// Automatic selection
    Auto = 0,
    /// Compiler backend
    Compiler = 1,
    /// Interpreter backend
    Interpreter = 2,
}

/// Sandbox type
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PVMSandbox {
    /// Automatic selection
    Auto = 0,
    /// Linux sandbox
    Linux = 1,
    /// Generic sandbox
    Generic = 2,
}

/// Creates a PolkaVM configuration with the specified parameters
#[no_mangle]
pub unsafe extern "C" fn pvm_config_create(memory_size: u32) -> *mut PVMConfig {
    let config = Box::new(PVMConfig {
        memory_size,
        allow_dynamic_paging: true,
        worker_count: 1,
        backend: PVMBackend::Auto as u32,
        sandbox: PVMSandbox::Auto as u32,
    });
    Box::into_raw(config)
}

/// Sets whether to allow dynamic paging
#[no_mangle]
pub unsafe extern "C" fn pvm_config_set_allow_dynamic_paging(config: *mut PVMConfig, allow: bool) {
    if !config.is_null() {
        (*config).allow_dynamic_paging = allow;
    }
}

/// Sets the number of worker threads
#[no_mangle]
pub unsafe extern "C" fn pvm_config_set_worker_count(config: *mut PVMConfig, count: u32) {
    if !config.is_null() {
        (*config).worker_count = count;
    }
}

/// Sets the backend type
#[no_mangle]
pub unsafe extern "C" fn pvm_config_set_backend(config: *mut PVMConfig, backend: PVMBackend) {
    if !config.is_null() {
        (*config).backend = backend as u32;
    }
}

/// Sets the sandbox type
#[no_mangle]
pub unsafe extern "C" fn pvm_config_set_sandbox(config: *mut PVMConfig, sandbox: PVMSandbox) {
    if !config.is_null() {
        (*config).sandbox = sandbox as u32;
    }
}

/// Frees memory occupied by the configuration
#[no_mangle]
pub unsafe extern "C" fn pvm_config_free(config: *mut PVMConfig) {
    if !config.is_null() {
        drop(Box::from_raw(config));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_create_free() {
        unsafe {
            let config = pvm_config_create(1024 * 1024);
            assert!(!config.is_null());
            pvm_config_free(config);
        }
    }
}
