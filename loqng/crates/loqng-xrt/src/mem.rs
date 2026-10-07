//! Guest memory, in two shapes, chosen by how wide the host's pointers are.
//!
//! Every translated load and store goes through here, so this is the shape of
//! the engine's inner loop and the single biggest lever on its speed.
//!
//! **On a 64-bit host** the whole 32-bit guest space fits in 4 GB of *address
//! space*, which costs nothing until it is committed. One reservation, and a
//! guest load is `base + a`: one instruction, with the base hoisted out of
//! the loop. Reserved is not committed, so an address outside a mapped region
//! is `PAGE_NOACCESS` and faults rather than quietly reading another region.
//!
//! **On a 32-bit host** — armv6 and armv7 — there is no 4 GB to reserve, and
//! a `usize` cannot even name it. The fallback is a page table of host
//! pointers: one extra dependent load per access, and about 45x real time
//! against the flat window's 82x. Both are byte-identical; only the speed
//! differs.
//!
//! The two present exactly the same API, and `xtask engcorpus` is the gate
//! for both.

use std::cell::Cell;

/// Page size for the 32-bit lookup table, and the commit granularity of the
/// 64-bit window.
#[allow(dead_code)]
const PAGE: u32 = 4096;

/// Apple Silicon pages are 16 KB, and `mprotect` refuses an address that is
/// not aligned to one. 16 KB on every Apple target keeps one universal binary
/// honest under Rosetta too, where the page is 4 KB and 16 KB is merely coarser.
#[cfg(all(target_pointer_width = "64", target_vendor = "apple"))]
const COMMIT: u32 = 16384;
#[cfg(all(target_pointer_width = "64", not(target_vendor = "apple")))]
const COMMIT: u32 = PAGE;

// ===========================================================================
// 64-bit: one flat window
// ===========================================================================

#[cfg(target_pointer_width = "64")]
mod imp {
    use super::{Cell, COMMIT};

    /// 4 GB of address space, which is all a `u32` can name.
    const SPACE: usize = 1usize << 32;

    pub struct Mem {
        base: *mut u8,
        regions: Vec<(u32, u32)>,
        last: Cell<usize>,
    }

    impl Drop for Mem {
        fn drop(&mut self) {
            unsafe { sys::release(self.base, SPACE) };
        }
    }

    impl Mem {
        pub fn new() -> Self {
            let base = unsafe { sys::reserve(SPACE) };
            assert!(
                !base.is_null(),
                "could not reserve 4 GB of address space for the guest"
            );
            Mem {
                base,
                regions: Vec::new(),
                last: Cell::new(0),
            }
        }

        /// Commit `len` bytes at `base`, zeroed, without building them on the
        /// host heap first. The heap is 96 MB and the stacks are 8 and 4, so
        /// a `Vec` of them would be allocated, zeroed, copied and dropped for
        /// nothing.
        pub fn zeroed(&mut self, base: u32, len: u32) {
            self.commit(base, len as u64);
            self.regions.push((base, len));
        }

        pub fn map(&mut self, base: u32, data: Vec<u8>) {
            self.commit(base, data.len() as u64);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.base.add(base as usize),
                    data.len(),
                );
            }
            self.regions.push((base, data.len() as u32));
        }

        /// Commitment is by host page, so the page at each end of a region
        /// that is not page aligned becomes readable in full. Two regions may
        /// share such a page; committing twice is harmless, and `regions`
        /// still knows the exact extents.
        fn commit(&mut self, base: u32, len: u64) {
            let end = base as u64 + len;
            for &(b, n) in &self.regions {
                assert!(
                    end <= b as u64 || base as u64 >= b as u64 + n as u64,
                    "region 0x{base:08x}+{len} overlaps 0x{b:08x}+{n}"
                );
            }
            let first = base & !(COMMIT - 1);
            let last = ((end as u32).wrapping_add(COMMIT - 1)) & !(COMMIT - 1);
            let span = if last == 0 {
                SPACE - first as usize
            } else {
                (last - first) as usize
            };
            unsafe {
                let at = self.base.add(first as usize);
                assert!(
                    sys::commit(at, span),
                    "could not commit {span} bytes at guest 0x{first:08x}"
                );
            }
        }

        /// # Safety
        ///
        /// `a` is a `u32` and the window is 4 GB, so `base + a` is always
        /// inside the reservation — there is no arithmetic to get wrong. An
        /// address outside a mapped region is still reserved, so it faults on
        /// access rather than reading another region's bytes.
        #[inline(always)]
        pub(super) fn at(&self, a: u32) -> *mut u8 {
            unsafe { self.base.add(a as usize) }
        }

        pub(super) fn extents(&self) -> (&[(u32, u32)], &Cell<usize>) {
            (&self.regions, &self.last)
        }
    }

    // ---- reserving and committing, without a dependency -------------------
    //
    // `loqng-xrt` has no dependencies and is not going to grow any, so the
    // three calls it needs are declared here. On Windows they resolve through
    // `kernel32` and on Linux through libc, both of which `std` already links.

    #[cfg(windows)]
    mod sys {
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const MEM_RELEASE: u32 = 0x8000;
        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_READWRITE: u32 = 0x04;

        extern "system" {
            fn VirtualAlloc(at: *mut u8, size: usize, kind: u32, prot: u32) -> *mut u8;
            fn VirtualFree(at: *mut u8, size: usize, kind: u32) -> i32;
        }

        pub unsafe fn reserve(size: usize) -> *mut u8 {
            VirtualAlloc(std::ptr::null_mut(), size, MEM_RESERVE, PAGE_NOACCESS)
        }

        pub unsafe fn commit(at: *mut u8, size: usize) -> bool {
            !VirtualAlloc(at, size, MEM_COMMIT, PAGE_READWRITE).is_null()
        }

        pub unsafe fn release(at: *mut u8, _size: usize) {
            VirtualFree(at, 0, MEM_RELEASE);
        }
    }

    // Linux and macOS, and only on a 64-bit host, which is why `off` being a
    // 64-bit `off_t` is safe to assume: the 32-bit targets never reach here.
    // The flags are where the two differ; Darwin ignores MAP_NORESERVE and
    // never overcommits a PROT_NONE mapping anyway.
    #[cfg(unix)]
    mod sys {
        const PROT_NONE: i32 = 0;
        const PROT_READ: i32 = 1;
        const PROT_WRITE: i32 = 2;
        const MAP_PRIVATE: i32 = 2;
        #[cfg(target_vendor = "apple")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_vendor = "apple")]
        const MAP_NORESERVE: i32 = 0x40;
        #[cfg(not(target_vendor = "apple"))]
        const MAP_ANONYMOUS: i32 = 0x20;
        #[cfg(not(target_vendor = "apple"))]
        const MAP_NORESERVE: i32 = 0x4000;

        extern "C" {
            fn mmap(at: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
            fn mprotect(at: *mut u8, len: usize, prot: i32) -> i32;
            fn munmap(at: *mut u8, len: usize) -> i32;
        }

        pub unsafe fn reserve(size: usize) -> *mut u8 {
            let p = mmap(
                std::ptr::null_mut(),
                size,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                -1,
                0,
            );
            if p as isize == -1 {
                std::ptr::null_mut()
            } else {
                p
            }
        }

        pub unsafe fn commit(at: *mut u8, size: usize) -> bool {
            mprotect(at, size, PROT_READ | PROT_WRITE) == 0
        }

        pub unsafe fn release(at: *mut u8, size: usize) {
            munmap(at, size);
        }
    }
}

// ===========================================================================
// 32-bit: a page table of host pointers
// ===========================================================================

#[cfg(not(target_pointer_width = "64"))]
mod imp {
    use super::{Cell, PAGE};

    const PAGE_BITS: u32 = 12;
    const PAGES: usize = 1 << (32 - PAGE_BITS);

    struct Region {
        base: u32,
        len: u32,
        data: Vec<u8>,
    }

    pub struct Mem {
        regions: Vec<Region>,
        /// Where guest page `a >> PAGE_BITS` lives on the host, or null if
        /// the page is not wholly inside one region.
        page: Vec<*mut u8>,
        extent: Vec<(u32, u32)>,
        last: Cell<usize>,
    }

    impl Mem {
        pub fn new() -> Self {
            Mem {
                regions: Vec::new(),
                page: vec![std::ptr::null_mut(); PAGES],
                extent: Vec::new(),
                last: Cell::new(0),
            }
        }

        pub fn zeroed(&mut self, base: u32, len: u32) {
            self.map(base, vec![0; len as usize]);
        }

        /// A region's bytes never move once mapped: `regions` may reallocate,
        /// but that moves the `Region` structs, not the heap buffers the page
        /// table points into. Nothing unmaps.
        pub fn map(&mut self, base: u32, mut data: Vec<u8>) {
            let end = base as u64 + data.len() as u64;
            for r in &self.regions {
                assert!(
                    end <= r.base as u64 || base as u64 >= r.base as u64 + r.len as u64,
                    "region 0x{base:08x}+{} overlaps 0x{:08x}+{}",
                    data.len(),
                    r.base,
                    r.len
                );
            }
            // Only pages wholly inside the region get a pointer. The ragged
            // ends of an unaligned region stay null and take the slow path;
            // regions are disjoint, so a whole page belongs to at most one.
            let host = data.as_mut_ptr();
            let step = PAGE as u64;
            let mut at = (base as u64 + step - 1) & !(step - 1);
            let stop = end & !(step - 1);
            while at < stop {
                self.page[(at >> PAGE_BITS) as usize] =
                    unsafe { host.add((at - base as u64) as usize) };
                at += step;
            }
            let len = data.len() as u32;
            self.extent.push((base, len));
            self.regions.push(Region { base, len, data });
        }

        /// # Safety
        ///
        /// A non-null page entry proves the whole page is mapped, and ARM
        /// requires `ldr`/`ldrh` to be aligned, so an access through one can
        /// never straddle the end of the page. The ragged ends go to `edge`,
        /// which searches the regions and proves the same thing.
        #[inline(always)]
        pub(super) fn at(&self, a: u32) -> *mut u8 {
            let p = unsafe { *self.page.get_unchecked((a >> PAGE_BITS) as usize) };
            if p.is_null() {
                return self.edge(a);
            }
            unsafe { p.add((a & (PAGE - 1)) as usize) }
        }

        #[inline(never)]
        #[cold]
        fn edge(&self, a: u32) -> *mut u8 {
            for (k, r) in self.regions.iter().enumerate() {
                let off = a.wrapping_sub(r.base) as usize;
                if a >= r.base && off < r.len as usize {
                    self.last.set(k);
                    return unsafe { r.data.as_ptr().add(off) as *mut u8 };
                }
            }
            panic!(
                "translated code touched unmapped memory at 0x{a:08x}{}",
                super::super::where_from()
            );
        }

        pub(super) fn extents(&self) -> (&[(u32, u32)], &Cell<usize>) {
            (&self.extent, &self.last)
        }
    }
}

pub use imp::Mem;

// ===========================================================================
// The accessors, which are the same either way
// ===========================================================================

impl Mem {
    /// Memory holding a module image (see the generated `*_image.rs`).
    pub fn with_image(image: &[(u32, &[u8])]) -> Self {
        let mut m = Mem::new();
        for (base, bytes) in image {
            m.map(*base, bytes.to_vec());
        }
        m
    }

    /// Whether `n` bytes at `a` are inside a mapped region. The debug
    /// assertions and the diagnostics use it; the accessors do not.
    pub fn mapped(&self, a: u32, n: u32) -> bool {
        let (regions, last) = self.extents();
        let hit = |&(b, len): &(u32, u32)| a >= b && (a - b) as u64 + n as u64 <= len as u64;
        if regions.get(last.get()).map_or(false, hit) {
            return true;
        }
        match regions.iter().position(hit) {
            Some(k) => {
                last.set(k);
                true
            }
            None => false,
        }
    }

    #[inline(always)]
    pub fn r8(&self, a: u32) -> u8 {
        debug_assert!(self.mapped(a, 1), "ldrb from unmapped 0x{a:08x}");
        unsafe { *self.at(a) }
    }

    #[inline(always)]
    pub fn r16(&self, a: u32) -> u16 {
        debug_assert!(a & 1 == 0, "unaligned ldrh at 0x{a:08x}");
        debug_assert!(self.mapped(a, 2), "ldrh from unmapped 0x{a:08x}");
        unsafe { u16::from_le((self.at(a) as *const u16).read_unaligned()) }
    }

    #[inline(always)]
    pub fn r32(&self, a: u32) -> u32 {
        debug_assert!(a & 3 == 0, "unaligned ldr at 0x{a:08x}");
        debug_assert!(self.mapped(a, 4), "ldr from unmapped 0x{a:08x}");
        unsafe { u32::from_le((self.at(a) as *const u32).read_unaligned()) }
    }

    #[inline(always)]
    pub fn w8(&mut self, a: u32, v: u8) {
        debug_assert!(self.mapped(a, 1), "strb to unmapped 0x{a:08x}");
        unsafe { *self.at(a) = v };
    }

    #[inline(always)]
    pub fn w16(&mut self, a: u32, v: u16) {
        debug_assert!(a & 1 == 0, "unaligned strh at 0x{a:08x}");
        debug_assert!(self.mapped(a, 2), "strh to unmapped 0x{a:08x}");
        unsafe { (self.at(a) as *mut u16).write_unaligned(v.to_le()) };
    }

    #[inline(always)]
    pub fn w32(&mut self, a: u32, v: u32) {
        debug_assert!(a & 3 == 0, "unaligned str at 0x{a:08x}");
        debug_assert!(self.mapped(a, 4), "str to unmapped 0x{a:08x}");
        unsafe { (self.at(a) as *mut u32).write_unaligned(v.to_le()) };
    }

    pub fn read(&self, a: u32, n: usize) -> Vec<u8> {
        assert!(
            self.mapped(a, n as u32),
            "reading {n} bytes from unmapped 0x{a:08x}{}",
            super::where_from()
        );
        unsafe { std::slice::from_raw_parts(self.at(a), n).to_vec() }
    }

    pub fn write(&mut self, a: u32, bytes: &[u8]) {
        assert!(
            self.mapped(a, bytes.len() as u32),
            "writing {} bytes to unmapped 0x{a:08x}{}",
            bytes.len(),
            super::where_from()
        );
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.at(a), bytes.len());
        }
    }
}

impl Default for Mem {
    fn default() -> Self {
        Mem::new()
    }
}
