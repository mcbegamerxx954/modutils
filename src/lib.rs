use core::slice;
use std::{
    cell::OnceCell,
    fs,
    ops::Deref,
    ptr::{self, slice_from_raw_parts},
};

use atoi::FromRadix16;
use bstr::ByteSlice;
use findshlibs::{Segment, SharedLibrary, TargetSharedLibrary};
use plt_rs::DynamicLibrary;
use region::{Protection, protect_with_handle};
use tinypatscan::Pattern;
fn main() {
    println!("Hello, world!");
}
pub struct Module<'e> {
    code_segments: Vec<MemoryRange>,
    // This is basically gambling but whatever
    // bytes: &'static [u8],
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
fn has_subslice(slice: &[u8], subslice: &[u8]) -> bool {
    slice
        .windows(subslice.len())
        .find(|s| *s == subslice)
        .is_some()
}
impl<'e> Module<'e> {
    pub fn find(name: &str) -> Self {
        // let sus = SimpleMapRange::find_library(&name).unwrap();
        let mut code_segments = Vec::new();
        TargetSharedLibrary::each(|lib| {
            if has_subslice(lib.name().as_encoded_bytes(), name.as_bytes()) {
                for code_segment in lib.segments().filter(|y| y.is_code() && y.is_load()) {
                    let range = MemoryRange::new(
                        code_segment.actual_virtual_memory_address(lib).0,
                        code_segment.len(),
                    );
                    code_segments.push(range);
                }
            }
        });
        let dynlib = find_dynlib(&name);
        Self {
            code_segments,
            // bytes: unsafe { core::slice::from_raw_parts(sus.start as *const u8, sus.size()) },
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
    pub fn find_signature<const LEN: usize>(&self, signature: Pattern<LEN>) -> Option<*const u8> {
        for mrange in &self.code_segments {
            if let Some(signature) = signature.simd_search(mrange.to_slice()) {
                return Some(signature as *const u8);
            }
        }
        None
    }
}

fn find_dynlib<'e>(name: &str) -> DynamicLibrary<'e> {
    let libs = plt_rs::collect_modules();
    let lib = libs.into_iter().find(|n| n.name().contains(name)).unwrap();
    DynamicLibrary::initialize(lib).unwrap()
} // A very minimal map range
#[derive(Debug)]
struct SimpleMapRange {
    start: usize,
    size: usize,
}

impl SimpleMapRange {
    /// Get the address where this range starts
    const fn start(&self) -> usize {
        self.start
    }

    /// Get the address where this range ends
    const fn size(&self) -> usize {
        self.size
    }
}
impl SimpleMapRange {
    fn find_library(lib: &str) -> Result<SimpleMapRange, Box<dyn std::error::Error>> {
        let contents = fs::read("/proc/self/maps")?;
        for line in contents.lines() {
            if line.trim_ascii().is_empty() {
                continue;
            }
            // Not too pretty but this method prevents crashes
            let Some((addr_start, addr_end)) = parse_range(line, lib) else {
                continue;
            };
            let start = usize::from_radix_16(addr_start).0;
            let end = usize::from_radix_16(addr_end).0;
            //            log::info!("Found libminecraftpe.so at: {:x}-{:x}", start, end);
            return Ok(SimpleMapRange {
                start,
                size: end - start,
            });
        }

        Err("libminecraftpe.so not found in memory maps".into())
    }
}
/// Separated into function due to option spam
fn parse_range<'e>(buf: &'e [u8], name: &str) -> Option<(&'e [u8], &'e [u8])> {
    let mut line = buf.split(|v| v.is_ascii_whitespace());
    let addr_range = line.next()?;
    let perms = line.next()?;
    let pathname = line.next_back()?;
    if perms.contains(&b'x') && pathname.ends_with_str(name) {
        return addr_range.split_once_str(b"-");
    }
    None
}
unsafe fn write_mem(buf: &[u8], addr: *mut u8) -> Result<(), region::Error> {
    unsafe {
        let _handle = protect_with_handle(addr, buf.len(), Protection::READ_WRITE)?;
        ptr::copy_nonoverlapping(buf.as_ptr(), addr, buf.len());
        clear_cache::clear_cache(addr.cast_const(), addr.add(buf.len()).cast_const());
        Ok(())
    }
}
