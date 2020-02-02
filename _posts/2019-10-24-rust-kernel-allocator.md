---
title: "Rust-OS Kernel buddy allocator - Part 1: Creating a simple allocator"
categories: Kernel Rust Coding
tags: rust kernel allocator
---

This relates to my very-much-in-development kernel in Rust: <https://github.com/nikofil/rust-os> 

If you're wondering how I managed to get this far without knowing anything about a kernel, my code is based on the excellent blog posts over at <https://os.phil-opp.com>. Mostly the first, lower level edition.

## Allocating a page

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
* Second, we want to be a bit smart about this and give back pages (or frames) of a fixed size (here, 0x1000 or 4096 bytes). We maybe could get away with using a different page size, but some things that were made with that amount of memory in mind (ie. page tables), so let's with go the easy way.
* Third, this struct needs to be static (for Rust to be able to use it from its global allocator) and also can be transferred across threads for the same reason. Rust complains about us sending a `MemoryAreaIter` accross threads (because it contains pointers) but we can just assure it that it's okay by implementing the `Send` marker for our frame allocator.

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

// shh it's ok pointers are thread-safe
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
            crate::println!("- Allocated new page");
            Some(frame)
        } else { // go to next area and try again
            self.next_area();
            crate::println!("- Going to next memory area");
            self.allocate()
        }
    }
}
```

## Getting Rust to use our allocator

Alright Rust, I made your allocator! Let me use the heap now!

```rust
    let mut x: Vec<u8> = Vec::new();
    x.push(0);
```

Of course, Rust doesn't appreciate all of our effort:

```
error: no global memory allocator found but one is required; link to std or add `#[global_allocator]` to a static item that implements the GlobalAlloc trait.

error: `#[alloc_error_handler]` function required, but not found

error: aborting due to 2 previous errors
```

We need to hold its hand and tell it how to use our allocator by making a struct that implements `GlobalAlloc`. We also need to define an error handler for when things go wrong. That sounds fairly simple, actually!

Also, this allocator needs to be static, naturally, as having it go out of scope in the middle of our program would be no good.

Alright, let's start with the easy part: Handling errors! At this point we can't do much to handle an allocation error, so we just panic.

```rust
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
```

In fact, the `-> !` return type says that this function is never supposed to return (so, either an infinite loop or an exit) so I don't think we're supposed to handle anything anyway. Great! Now let's do the actually useful part. We start by creating a struct that implements `GlobalAlloc`.

```rust
pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unimplemented!()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unimplemented!()
    }
}
```

The interface is as simple as can be. For allocating we have the required layout (the required size and alignment of the returned memory area) and we return the (virtual) address of that area. For de-allocating we are given a pointer and the layout of the freed area.

How can we keep track of freed pages, though? Our frame allocator is simply an iterator that iterates over a static struct (the static `BootInformation` given to us by the bootloader). We can't just add pages back to it. A `Vec` would be ideal here but, well, we need an allocator to use the `Vec` that we want for implementing our allocator!

Actually, that's slightly misleading. We only need the `Vec` for freeing a page and we don't need to free a page until after we have allocated a page. So this seemingly circular problem can be broken down into two simple steps:
1. Set up the allocator to only be able to allocate pages
2. Allocate a `Vec` for keeping free pages, after which we can also free pages

I created an additional static struct to help deal with this. It has two fields: 
* `frame_allocator` contains the allocator that we created previously and is initialized on the first step
* `free_frames` is the `Vec<PhysAddr>` which contains the freed frames and is initialized on the second step
Both are protected by a `Mutex` so that Rust doesn't complain (rightly so, as we might someday want to have multiple threads!)

Finally the method `init_global_alloc` performs both steps: It initializes the `frame_allocator` member after which Rust should be able to allocate on the heap. After that it performs its first allocation: a `Vec` with capacity 200! This allows our `free_frames` list to store several frame addresses before needing a reallocation.

```rust
struct AllocatorInfo {
    frame_allocator: Mutex<Option<&'static mut dyn FrameSingleAllocator>>,
    free_frames: Mutex<Option<Vec<PhysAddr>>>,
}

lazy_static! {
    static ref ALLOCATOR_INFO: AllocatorInfo = AllocatorInfo {
        frame_allocator: Mutex::new(None),
        free_frames: Mutex::new(None),
    };
}

pub fn init_global_alloc(frame_alloc: &'static mut dyn FrameSingleAllocator) {
    // set the frame allocator as our current allocator
    ALLOCATOR_INFO.frame_allocator.lock().replace(frame_alloc);
    let old_free_frames = ALLOCATOR_INFO.free_frames.lock().take();
    // avoid dropping this inside a lock so we don't trigger a free
    // while holding the lock
    drop(old_free_frames);
    ALLOCATOR_INFO
        .free_frames
        .lock()
        .replace(Vec::with_capacity(200));
}
```

Having created this struct we can go ahead and implement the actual global allocator:
(at this point I added the great `if_chain` crate to my project to deal with long chains of `if let`s)

```rust
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if_chain! {
            // try locking the free_frames mutex (this locking fails when dealloc needs to allocate
            // more space for its Vec and calls this as it already holds this lock!)
            if let Some(ref mut guard) = ALLOCATOR_INFO.free_frames.try_lock();
            // get as mutable
            if let Some(ref mut free) = guard.as_mut();
            // get last page (if it exists)
            if let Some(page) = free.pop();
            // if a page exists
            if let Some(virt) = page.to_virt();
            // return the page
            then {
                crate::println!("Reusing! ^_^ {:x}", virt.addr());
                return virt.to_ref();
            }
        }
        if_chain! {
            // lock the frame allocator
            if let Some(ref mut allocator) = ALLOCATOR_INFO.frame_allocator.lock().as_mut();
            // get a physical page from it
            if let Some(page) = allocator.allocate();
            // convert it to virtual (add 0xC0000000)
            if let Some(virt) = page.to_virt();
            // return the page
            then {
                crate::println!("Allocated! ^_^ {:x}", virt.addr());
                return virt.to_ref();
            }
        }
        null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::println!("Deallocating: {:x}", ptr as u64);
        if_chain! {
            // try converting the deallocated virtual page address to the physical address
            if let Some((phys_addr, _)) = VirtAddr::new(ptr as u64).to_phys();
            // try locking the free frames list (this fails if we've already locked free_frames
            // for some reason, i.e. if we're in the middle of reallocating it due to a push to it)
            if let Some(ref mut guard) = ALLOCATOR_INFO.free_frames.try_lock();
            // get as mutable
            if let Some(ref mut free) = guard.as_mut();
            // add the physical address to the free frames list
            then {
                free.push(phys_addr);
            }
        }
        crate::println!("Deallocated! v_v {:x}", ptr as u64);
    }
}
```

## Testing the global allocator

Finally we can actually allocate stuff! Let's see how the global allocator behaves in an example.

```rust
#[global_allocator]
static ALLOCATOR: global_alloc::Allocator = global_alloc::Allocator;

pub fn start(boot_info: &'static BootInformation) -> ! {
    init_gdt();
    unsafe {
        let alloc = frame_alloc::SimpleAllocator::new(&boot_info);
        frame_alloc::BOOTINFO_ALLOCATOR.replace(alloc);
        global_alloc::init_global_alloc(frame_alloc::BOOTINFO_ALLOCATOR.as_mut().unwrap());
    }
    {
        println!("Before first Vec");
        let mut x: Vec<u32> = Vec::new();
        x.push(123);
        println!("{}", x[0]);
    }
    {
        println!("Before second Vec");
        let mut x: Vec<u32> = Vec::new();
        x.push(456);
        println!("{}", x[0]);
    }
    println!("After second Vec");
```

This outputs (with comments):
```
Before first Vec
- Going to next memory area # frame allocator proceeds to next memory area
- Allocated new page        # frame allocator gives the page to global allocator
* Allocated! ^_^ c04ae000   # global allocator gives us the virtual addr of that page
123
* Deallocating: c04ae000    # we give the page back to the allocator
- Allocated new page        # a new page is allocated to hold the Vec with the freed page
* Allocated! ^_^ c04af0000  # that page is given to the allocator, by the allocator!
* Deallocated! v_v c04ae000 # finally the page we gave back is added to the free list
Before second Vec
* Reusing! ^_^ c04ae000     # we need a new page now but we already have one in the free list
456
* Deallocating: c04ae000    # we give that page back to the allocator for a second time
* Deallocated! v_v c04ae000 # it has been added to the free list successfully
After second Vec
```

All works well! :) We can now proceed (in the next post) with making our allocator smarter so that we don't waste an entire page every time we want to allocate anything and so that we can allocate blocks larger than 4096 bytes.

Next post: [Part 2: Buddy allocator]({% post_url 2019-11-24-rust-buddy-allocator %})
