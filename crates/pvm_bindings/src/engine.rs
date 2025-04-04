use crate::PVMConfig;
use polkavm::{BackendKind, Config, Engine, SandboxKind};
use std::ptr;

/// Structure representing a PolkaVM engine
#[repr(C)]
pub struct PVMEngine {
    pub(crate) engine: Engine,
}

/// Initializes a PolkaVM engine with the given configuration
#[no_mangle]
pub unsafe extern "C" fn pvm_engine_new(config_ptr: *const PVMConfig) -> *mut PVMEngine {
    if config_ptr.is_null() {
        return ptr::null_mut();
    }

    let config = &*config_ptr;
    let mut config_rust = Config::default();

    // Configure the parameters
    config_rust.set_allow_dynamic_paging(config.allow_dynamic_paging);
    config_rust.set_worker_count(config.worker_count as usize);

    // Set the backend
    if let Some(backend) = match config.backend {
        1 => Some(BackendKind::Compiler),
        2 => Some(BackendKind::Interpreter),
        _ => None,
    } {
        config_rust.set_backend(Some(backend));
    }

    // Set the sandbox
    if let Some(sandbox) = match config.sandbox {
        1 => Some(SandboxKind::Linux),
        2 => Some(SandboxKind::Generic),
        _ => None,
    } {
        config_rust.set_sandbox(Some(sandbox));
    }

    match Engine::new(&config_rust) {
        Ok(engine) => {
            let engine_box = Box::new(PVMEngine { engine: engine });
            Box::into_raw(engine_box)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Frees memory occupied by the engine
#[no_mangle]
pub unsafe extern "C" fn pvm_engine_free(engine: *mut PVMEngine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}
