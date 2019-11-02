---
title: "Rust-OS Kernel buddy allocator"
tags: rust kernel allocator
---

This relates to my very-much-in-development kernel in Rust: <https://github.com/nikofil/rust-os>

I'm going to be writing this at the same time of implementing it on my own kernel. Let's see how it goes. :)

If you're wondering how I managed to get this far without knowing anything about a kernel, my code is based on the excellent blog posts over at <https://os.phil-opp.com>. Mostly the first, lower level edition.

## Part 0: Allocating a page

Before doing implementing any fancy memory allocation algorithm, we need to know how much memory is available. Unfortunately this information is only available in the very early stages of booting so we have to modify our crappy boot code to pass that information over. Fortunately, however, we are using multiboot2 for our bootloader which gives us a pointer to a struct with all this information in ebx.

Thankfully the multiboot2 crate gives us a way to parse this struct which I don't care much about parsing myself. So we're going to need to pass the (physical) address to our Rust entry point, convert it to a virtual address (essentially add 0xC0000000 which is our load base) and use the crate to get a list of empty pages.

The bootloader gives us this pointer in `ebx` which gets mangled for some reason during my boot process, so I'm going to save it in the stack and pass it using `edi` (the conventional register for the first argument of a function in ua64) to my start function.

```diff
 _start:
     mov esp, _stack_top_low
+    push ebx
     call _multiboot_check
     call _cpuid_check
     call _long_mode_check
     call _setup_page_table
     call _enable_paging
     mov eax, _gdt64_pointer_low
     lgdt [eax]
+    pop ebx
     call _ua64_mode_entry

 _ua64_mode_entry:
     mov edx, 0xC0000000
     add esp, edx
     mov eax, _ua64_mode_entry_high
     jmp eax
     _ua64_mode_entry_high:
     mov dword [_p3_table], 0
+    mov edi, ebx
     jmp _gdt64_code_off:ua64_mode_start
```

We can now read that first argument as a `u64` which we need to convert to a `usize` with the virtual address.

```rust
    let boot_info: &multiboot2::BootInformation = unsafe {
        multiboot2::load(
            mem::PhysAddr::new(multiboot_info_addr)
                .to_virt()
                .unwrap()
                .addr() as usize
        )
    };
```

Surprisingly, it just works!

Now we have a struct that can give us a list of memory areas that we can use. So what do we do with these?

Let's make something that can give us pages back!

```rust
pub trait FrameSingleAllocator: Send {
    unsafe fn allocate(&mut self) -> Option<PhysAddr>;
}
```

Simple enough to start with - what's difficult about it?

* First, some of the memory areas that we get back are already in use by the kernel. Multiboot has loaded our kernel into the start, but that's still a usable memory area. Of course you probably don't want to hand over the memory that stores your kernel when allocating something and getting your code overwritten. That leads to some very nasty bugs. We can use `boot_info.end_address()` to get the end address of our kernel so we can only give out pages after its end.
* Second, we want to be a bit smart about this and give back pages (or frames) of a fixed size (here, 0x1000 or 4096 bytes). We maybe could get away with using a different page size, but some things that (ie. page tables) were made with that amount of memory in mind, so let's with go the easy way.
* Third, this struct needs to be static (for Rust to be able to use it from its global allocator) and also thread safe for the same reason. As we make sure the global allocator implementation is thread safe using a Mutex we can just assure Rust that no thread-unsafe tomfoolery will take place here.

To do these things, we iterate through the available memory areas. We make sure we have enough memory for a frame at each step, starting after the end of our kernel and having an address aligned with our page size. If we can't meet that criteria we go to the next memory area, until we have none left.

So, finally, this is the implementation for the simple page allocator. It can only give us new pages and can't deallocate unused pages, but that's all it has to do.

```rust
pub static mut BOOTINFO_ALLOCATOR: Option<SimpleAllocator> = None;

pub trait FrameSingleAllocator: Send {
    unsafe fn allocate(&mut self) -> Option<PhysAddr>;
}

pub struct SimpleAllocator {
    kernel_end_phys: u64, // end address of our kernel sections (don't write before this!)
    mem_areas: MemoryAreaIter, // iter of memory areas
    cur_area: Option<(u64, u64)>, // currently used area's bounds
    next_page: usize, // next page no. in this area to return
}

// shh it's ok we only access this from a thread-safe struct
unsafe impl core::marker::Send for SimpleAllocator {} 

impl SimpleAllocator {
    pub unsafe fn new(boot_info: &BootInformation) -> SimpleAllocator {
        let mem_tag = boot_info.memory_map_tag().expect("Must have memory map tag");
        let mut mem_areas = mem_tag.memory_areas();
        let kernel_end = boot_info.end_address() as u64;
        let kernel_end_phys = VirtAddr::new(kernel_end).to_phys().unwrap().0.addr();
        let mut alloc = SimpleAllocator {
            kernel_end_phys,
            mem_areas,
            cur_area: None,
            next_page: 0,
        };
        alloc.next_area();
        alloc
    }

    fn next_area(&mut self) {
        self.next_page = 0;
        if let Some(mem_area) = self.mem_areas.next() {
            // get base addr and length for current area
            let base_addr = mem_area.base_addr;
            let area_len = mem_area.length;
            // start after kernel end
            let mem_start = max(base_addr, self.kernel_end_phys);
            let mem_end = base_addr + area_len;
            // memory start addr aligned with page size
            let start_addr = ((mem_start + FRAME_SIZE - 1) / FRAME_SIZE) * FRAME_SIZE;
            // memory end addr aligned with page size
            let end_addr = (mem_end / FRAME_SIZE) * FRAME_SIZE;
            self.cur_area = Some((start_addr, end_addr));
        } else {
            self.cur_area = None; // out of mem areas :(
        };
    }
}

impl FrameSingleAllocator for SimpleAllocator {
    unsafe fn allocate(&mut self) -> Option<PhysAddr> {
        // get current area start and end addr if we still have an area left
        let (start_addr, end_addr) = self.cur_area?;
        let frame = PhysAddr::new(start_addr + (self.next_page as u64 * FRAME_SIZE));
        // return a page from this area
        if frame.addr() + (FRAME_SIZE as u64) < end_addr {
            self.next_page += 1;
            crate::println!("allocating woo");
            Some(frame)
        } else { // go to next area and try again
            self.next_area();
            crate::println!("woah next area");
            self.allocate()
        }
    }
}
```
