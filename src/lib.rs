use std::{
    cell::OnceCell,
    fs,
    ops::Deref,
    ptr::{self, slice_from_raw_parts},
};

use atoi::FromRadix16;
use bstr::ByteSlice;
use plt_rs::DynamicLibrary;
use region::{Protection, protect_with_handle};
fn main() {
    println!("Hello, world!");
}
pub struct Module<'e> {
    name: String,
    // This is basically gambling but whatever
    // bytes: &'static [u8],
    option: DynamicLibrary<'e>,
}

impl<'e> Module<'e> {
    pub fn find(name: String) -> Self {
        // let sus = SimpleMapRange::find_library(&name).unwrap();
        let dynlib = find_dynlib(&name);
        Self {
            name,
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
        Ok(())
    }
}
