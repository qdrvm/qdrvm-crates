pub unsafe fn from_raw_parts<'a, T>(data: *const T, len: usize) -> &'a [T] {
    let data = if data.is_null() {
        core::ptr::NonNull::dangling().as_ptr()
    } else {
        data
    };
    core::slice::from_raw_parts(data, len)
}

pub unsafe fn from_raw_parts_mut<'a, T>(data: *mut T, len: usize) -> &'a mut [T] {
    let data = if data.is_null() {
        core::ptr::NonNull::dangling().as_ptr()
    } else {
        data
    };
    core::slice::from_raw_parts_mut(data, len)
}

/// Trait to expose rust type as C opaque type.
pub trait Opaque: Sized {
    /// Rust type.
    type Type;
    /// Null C pointer.
    fn null() -> *mut Self {
        std::ptr::null_mut()
    }
    /// Return rust value as C pointer.
    fn leak(value: Self::Type) -> *mut Self {
        Box::leak(Box::new(value)) as *mut Self::Type as *mut Self
    }
    /// Destroy rust value from C pointer.
    fn drop(ptr: *mut Self) {
        unsafe { drop(Box::from_raw(ptr)) }
    }
    /// Get reference to rust value from C pointer.
    fn arg(ptr: *const Self) -> &'static Self::Type {
        unsafe { &*(ptr as *const Self::Type) }
    }
    /// Get mutable reference to rust value from C pointer.
    fn arg_mut(ptr: *mut Self) -> &'static mut Self::Type {
        unsafe { &mut *(ptr as *mut Self::Type) }
    }
}
