use core::slice;
use std::{
    mem::transmute,
    ptr::{self},
};

use findshlibs::{Segment, SharedLibrary, TargetSharedLibrary};
use os_str_bytes::OsStrBytesExt;
use plt_rs::DynamicLibrary;
use region::{Protection, protect_with_handle};
use tinypatscan::{Algorithm, FinderIterator, StaticPattern};

pub struct Module<'e> {
    code_segments: Vec<MemoryRange>,
    option: DynamicLibrary<'e>,
}
pub struct MemoryRange {
    start: usize,
    len: usize,
}
impl MemoryRange {
    fn new(start: usize, len: usize) -> Self {
        MemoryRange { start, len }
    }
}
impl MemoryRange {
    fn to_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.start as *const u8, self.len) }
    }
}

impl<'e> Module<'e> {
    pub fn find(name: &str) -> Self {
        let mut code_segments = Vec::new();
        TargetSharedLibrary::each(|lib| {
            if lib.name().contains(name) {
                for code_segment in lib.segments().filter(|y| y.is_code() && y.is_load()) {
                    let range = MemoryRange::new(
                        code_segment.actual_virtual_memory_address(lib).into(),
                        code_segment.len(),
                    );
                    code_segments.push(range);
                }
            }
        });
        log::info!("We have {} code segments", code_segments.len());
        let dynlib = find_dynlib(&name);
        Self {
            code_segments,
            option: dynlib,
        }
    }
    pub fn replace_lib_import(&mut self, import_name: &str, fun: *const u8) -> Option<*const u8> {
        //        let dynlib = self.get_dynlib();
        let pltfn = self.option.try_find_function(import_name)?;
        let plt_fn_ptr = (self.option.library().addr() + pltfn.r_offset as usize) as *mut *const u8;
        const PTR_LEN: usize = std::mem::size_of::<usize>();

        unsafe {
            // Set the memory page to read, write
            let _handle = protect_with_handle(plt_fn_ptr, PTR_LEN, Protection::READ_WRITE)
                .expect("Mprotect failed");
            // Replace the function address
            let old_addr = plt_fn_ptr.replace(fun);
            Some(old_addr)
        }
    }
    pub fn find_signature<const LEN: usize>(
        &self,
        signature: &StaticPattern<LEN>,
    ) -> Option<*const u8> {
        if self.code_segments.is_empty() {
            panic!("huh no code segments??");
        }
        for mrange in &self.code_segments {
            let slice = mrange.to_slice();
            if let Some(signature) = signature.search(slice, Algorithm::Simd) {
                return Some(slice[signature..].as_ptr());
            }
        }
        None
    }

    fn to_real_address(&self, addr: usize, section: usize) -> *const u8 {
        (self.code_segments[section].start + addr) as *const u8
    }
    pub fn iter_find_signature<const LEN: usize>() {}
}

fn find_dynlib<'e>(name: &str) -> DynamicLibrary<'e> {
    let libs = plt_rs::collect_modules();
    let lib = libs.into_iter().find(|n| n.name().contains(name)).unwrap();
    DynamicLibrary::initialize(lib).unwrap()
}
pub unsafe fn write_mem(buf: &[u8], addr: *mut u8) -> Result<(), region::Error> {
    unsafe {
        let _handle = protect_with_handle(addr, buf.len(), Protection::READ_WRITE)?;
        ptr::copy_nonoverlapping(buf.as_ptr(), addr, buf.len());
        clear_cache::clear_cache(addr.cast_const(), addr.add(buf.len()).cast_const());
        Ok(())
    }
}
pub unsafe fn ptr_write<T>(ptr: *mut T, data: T) -> Result<(), region::Error> {
    unsafe {
        let _handle = protect_with_handle(ptr, size_of::<T>(), Protection::READ_WRITE)?;
        ptr.write_unaligned(data);
        clear_cache::clear_cache(ptr.cast_const(), ptr.add(size_of::<T>()).cast_const());
    }
    Ok(())
}
// Ill clean the lifetimes up later
pub struct SigFindIterator<'a, 'f, 'e, const SIZE: usize> {
    module: &'f Module<'e>,
    signature: StaticPattern<SIZE>,
    last_finder: FinderIterator<'a, SIZE>,
    module_section: usize,
}
impl<'a, 'f, 'e: 'a, const SIZE: usize> SigFindIterator<'a, 'f, 'e, SIZE> {
    pub fn new(module: &'e Module, signature: StaticPattern<SIZE>) -> Self {
        Self {
            module,
            signature,
            last_finder: signature.search_iter(module.code_segments[0].to_slice(), Algorithm::Simd),
            module_section: 0,
        }
    }
}
impl<'f: 'a, 'a, 'e: 'a, const SIZE: usize> Iterator for SigFindIterator<'a, 'f, 'e, SIZE> {
    type Item = *const u8;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sig) = self.last_finder.next() {
            return Some(self.module.to_real_address(sig, self.module_section));
        }
        while self.module_section <= self.module.code_segments.len() - 1 {
            let mut next_module = self.signature.search_iter(
                self.module.code_segments[self.module_section].to_slice(),
                Algorithm::Simd,
            );
            self.module_section += 1;
            if let Some(find) = next_module.next() {
                // SAFETY: There is basically no fucking way we would be ok anyways in a module gets unloaded at runtime.
                // no borrow checker can fix that, lets ignore the lifetime this time as we have no other way around this
                self.last_finder = next_module;
                return Some(self.module.to_real_address(find, self.module_section));
            }
        }
        None
    }
}
