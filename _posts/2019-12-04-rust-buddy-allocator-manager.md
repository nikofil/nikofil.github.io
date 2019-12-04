---
title: "Rust-OS Kernel buddy allocator - Part 3: Allocator manager"
categories: Kernel Rust Coding
tags: rust kernel buddy allocator
---

Previous post: [Part 2: Buddy allocator]({% post_url 2019-11-24-rust-buddy-allocator %})

We can use a single buddy allocator, given a continuous block of memory with the size of a power of 2. It's very probably however that this would waste a lot of memory, as our entire memory won't be a single block that is a power of 2. So what can we do?

Another issue that I ran into was the following: a buddy allocator contains vectors. A vector is a dynamic structure, which means some times it needs to resize when we push things to it, which means it might need to call the allocator itself. We've been to get around this issue with our frame allocator (since we only needed to allocate when de-allocating a block to the free list, and not while allocating). However in this case we have an allocation-in-allocation. Due to the allocator being behind a `RwLock` so that we can make sure no two threads / processes / whatever we decide to call them can mess up its state at the same time, if we need to allocate more space for a vec during our allocation, we end up in the unfavorable position of having to lock this lock while already holding it. This could be done through some horrible hack, or we could solve both things at once:

We could have many buddy allocators!

## Buddy allocator manager

That's my unimaginative name for the struct that holds all the buddy allocators. When we construct this struct we'll still be using the previous (frame) allocator, so on every memory allocation we get exactly 4096 bytes no matter how many we ask for. So let's try not to waste them.

The manager can hold many allocators, each of which will manage some amount of memory. Then, the manager can handle memory requests by looping through all its allocators and finding one that can handle the request. Simple! So what's the challenge?

Honestly, it's all about handling the memory. We need to split up the memory in chunks that can be used by a buddy allocator to not waste too much memory. For example, let's say we have a system with 7GiB. The best way to split that would be to have 3 allocators: 4, 2 and 1 GiB.

![Neat!](https://i.imgur.com/iYOXpB3.gif)

I opted for something a little less optimal. I made a function `fn get_mem_area_with_size(frame_alloc: &mut dyn FrameSingleAllocator, mem_size: u64)` which takes a frame allocator and a requested size. It pulls pages from the allocator until it has enough for the requested size (so `mem_size / FRAME_SIZE`). Of course it's possible that we don't have enough memory to fill that request, or that the next frame the frame allocator gives us is not located after the previous one so we can't use them together. In that case the function returns one or two memory areas that are smaller than the one requested. Then we create buddy allocators that handle these memory areas so that we don't waste them. For example, if we ask for 512 MiB but we only have 500 continuous MiB this function will return two memory areas of 256 and 128 MiB. The rest are lost but I don't care that much about it as it should be rare.

```rust
enum MemAreaRequest {
    Success((PhysAddr, PhysAddr)),
    SmallerThanReq((PhysAddr, PhysAddr), Option<(PhysAddr, PhysAddr)>),
    Fail,
}

impl BuddyAllocatorManager {
    fn get_mem_area_with_size(
        frame_alloc: &mut dyn FrameSingleAllocator,
        mem_size: u64,
    ) -> MemAreaRequest {
        // This function tries to find a continuous memory area as big as the one requested by
        // pulling pages from the frame allocator. If it doesn't find an area big enough immediately,
        // it might return one or two smaller ones (so that we don't leave memory unused for no reason
        // if it doesn't fit our purposes).
        if let Some(first_page) = unsafe { frame_alloc.allocate() } {
            let first_addr = first_page.addr();
            let mut last_addr = first_addr + FRAME_SIZE;
            // Keep pulling pages from the frame allocator until we hit the required memory size
            // or until we run out of memory or we get a block that is not after the previous block received.
            while let Some(next_page) = unsafe { frame_alloc.allocate() } {
                if next_page.addr() == last_addr {
                    last_addr += FRAME_SIZE;
                } else {
                    break;
                }
                if last_addr - first_addr == mem_size {
                    break;
                }
            }
            // If we found a memory area big enough, great! Return it.
            if last_addr - first_addr == mem_size {
                MemAreaRequest::Success((PhysAddr::new(first_addr), PhysAddr::new(last_addr)))
            } else {
                // If we found a smaller memory block, get the largest piece that is a power of 2
                // and also greater than a page size. We can use that to make a smaller buddy allocator.
                if let Some(first_memarea) = Self::get_largest_page_multiple(first_addr, last_addr) {
                    // Try to form a second such block with the left-over memory to not waste it.
                    let second_memarea = Self::get_largest_page_multiple(first_memarea.1.addr(), last_addr);
                    MemAreaRequest::SmallerThanReq(first_memarea, second_memarea)
                } else {
                    // This should never happen but let's be safe
                    MemAreaRequest::Fail
                }
            }
        } else {
            // Couldn't even pull a single page from the frame allocator :(
            MemAreaRequest::Fail
        }
    }

    fn get_largest_page_multiple(start: u64, end: u64) -> Option<(PhysAddr, PhysAddr)> {
        // Given a start and end address, try to find the largest memory size that can fit into that
        // area that is also a left shift of a FRAME_SIZE (ie. 4096, 8192, 16384 etc.)
        // We need this because our buddy allocator needs a memory area whose size is a power of 2
        // in order to be able to split it cleanly and efficiently.
        // Also, the smallest size of that memory area will be the FRAME_SIZE.
        let mem_len = end - start;
        if mem_len == 0 {
            None
        } else {
            // double page_mult while it still fits in this mem area
            let mut page_mult = FRAME_SIZE;
            while page_mult <= mem_len {
                page_mult <<= 1;
            }
            // we went over the limit so divide by two
            page_mult >>= 1;
            let start_addr = PhysAddr::new(start);
            Some((start_addr, start_addr.offset(page_mult)))
        }
    }
}
```

With these two helpers we can create the buddy allocator manager! It's pretty straightforward now. It simply needs to hold a list of buddy allocators. Then we will ask it to add a buddy allocator that handles a requested size of memory. It will do its best to find a memory chunk big enough for the request. Any smaller chunks it finds on the way, it simply adds them as smaller buddy allocators and keeps looking. If no more pages can be allocated from the frame allocator we stop.

Also of course it needs to support `alloc` and `dealloc`. In the case of `alloc` we loop through our allocators and try to lock each one and allocate with it. If that fails, we try the next one until we get an allocation (or until we run out of allocators!). This subtly solves our problem of double locking the lock that protects each allocator: When an allocator tries to allocate some memory for its internal vectors, we won't be able to lock it a second time so instead we'll use another allocator in the list to fulfill that request!

For `dealloc` we go through the list again and ask each allocator if it owns that piece of memory. If so we give it back to it and it does its buddy magic from the previous post. If we can't find which allocator it belongs to (for example in the case some memory that was allocated with the old frame allocator) it's simply wasted forever and can't be reclaimed. Sucks!

So here's the code dump:

```rust
pub struct BuddyAllocatorManager {
    buddy_allocators: RwLock<Vec<Mutex<BuddyAllocator>>>,
}

impl BuddyAllocatorManager {
    pub fn new() -> BuddyAllocatorManager {
        // Create an empty buddy allocator list. At this point we're still using the dumb page allocator.
        let buddy_allocators = RwLock::new(Vec::with_capacity(32));
        BuddyAllocatorManager { buddy_allocators }
    }

    pub fn add_memory_area(&self, start_addr: PhysAddr, end_addr: PhysAddr, block_size: u16) {
        // Add a new buddy allocator to the list with these specs.
        // As each one has some dynamic internal structures, we try to make it so that none of these
        // has to use itself when allocating these.
        let new_buddy_alloc = Mutex::new(BuddyAllocator::new(start_addr, end_addr, block_size));
        // On creation the buddy allocator constructor might lock the list of buddy allocators
        // due to the fact that it allocates memory for its internal structures (except for the very
        // first buddy allocator which still uses the previous, dumb allocator).
        // Therefore we first create it and then we lock the list in order to push the new
        // buddy allocator to the list.
        self.buddy_allocators.write().push(new_buddy_alloc);
    }

    pub fn add_mem_area_with_size(
        &self,
        frame_alloc: &mut dyn FrameSingleAllocator,
        mem_size: u64,
        block_size: u16,
    ) -> bool {
        // Find and create a buddy allocator with the memory area requested.
        // We use get_mem_area_with_size first to find the memory area.
        // That function might instead find one (or two) smaller memory areas if the current
        // memory block that we're pulling memory from isn't big enough.
        // In that case add these smaller ones but keep looping until we get a memory block
        // as big as the one requested.
        // If we run out of memory, we simply return false.
        loop {
            match Self::get_mem_area_with_size(frame_alloc, mem_size) {
                // Success! Found a memory area big enough for our purposes.
                MemAreaRequest::Success((mem_start, mem_end)) => {
                    serial_println!(
                        "* Adding requested mem area to BuddyAlloc: {} to {} ({})",
                        mem_start,
                        mem_end,
                        mem_end.addr() - mem_start.addr()
                    );
                    self.add_memory_area(mem_start, mem_end, block_size);
                    return true;
                }
                // Found one or two smaller memory areas instead, insert them and keep looking.
                MemAreaRequest::SmallerThanReq((mem_start, mem_end), second_area) => {
                    self.add_memory_area(mem_start, mem_end, block_size);
                    serial_println!(
                        "* Adding smaller mem area to BuddyAlloc: {} to {} ({})",
                        mem_start,
                        mem_end,
                        mem_end.addr() - mem_start.addr()
                    );
                    if let Some((mem_start, mem_end)) = second_area {
                        self.add_memory_area(mem_start, mem_end, block_size);
                        serial_println!(
                            "* Adding smaller mem area to BuddyAlloc: {} to {} ({})",
                            mem_start,
                            mem_end,
                            mem_end.addr() - mem_start.addr()
                        );
                    }
                }
                // Ran out of memory! Return false.
                MemAreaRequest::Fail => {
                    serial_println!(
                        "! Failed to find mem area big enough for BuddyAlloc: {}",
                        mem_size
                    );
                    return false;
                }
            }
        }
    }
}

unsafe impl GlobalAlloc for BuddyAllocatorManager {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Loop through the list of buddy allocators until we can find one that can give us
        // the requested memory.
        let allocation =
            self.buddy_allocators
                .read()
                .iter()
                .enumerate()
                .find_map(|(i, allocator)| {
                    // for each allocator
                    allocator.try_lock().and_then(|mut allocator| {
                        allocator
                            .alloc(layout.size(), layout.align())
                            .map(|allocation| {
                                // try allocating until one succeeds and return this allocation
                                serial_println!(
                                    " - BuddyAllocator #{} allocated {} bytes",
                                    i,
                                    layout.size()
                                );
                                serial_println!("{}", *allocator);
                                allocation
                            })
                    })
                });
        // Convert physical address to virtual if we got an allocation, otherwise return null.
        allocation
            .and_then(|phys| phys.to_virt())
            .map(|virt| virt.addr() as *mut u8)
            .unwrap_or(null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let virt_addr = VirtAddr::new(ptr as u64);
        if let Some((phys_addr, _)) = virt_addr.to_phys() {
            for (i, allocator_mtx) in self.buddy_allocators.read().iter().enumerate() {
                // for each allocator
                if let Some(mut allocator) = allocator_mtx.try_lock() {
                    // find the one whose memory range contains this address
                    if allocator.contains(phys_addr) {
                        // deallocate using this allocator!
                        allocator.dealloc(phys_addr, layout.size(), layout.align());
                        serial_println!(
                            " - BuddyAllocator #{} de-allocated {} bytes",
                            i,
                            layout.size()
                        );
                        serial_println!("{}", *allocator);
                        return;
                    }
                }
            }
        }
        serial_println!(
            "! Could not de-allocate virtual address: {} / Memory lost",
            virt_addr
        );
    }
}
```

## Constructing buddy allocators in a sort of sane manner

We're almost there! We still need to construct the manager with the tools that are given to us (which is essentially only the frame allocator) and to let Rust know how to use it.

In order to be able to use it, I altered slightly the `AllocatorInfo` struct from part 1 to add a `strategy` field, so called because it's supposed to be an implementation of the ["strategy pattern"](https://en.wikipedia.org/wiki/Strategy_pattern). However the result is rather restrictive for now as it only allows the buddy allocator implementation. This could be fixed if I wanted to support different allocation strategies in the future, but I really don't.

```rust
struct AllocatorInfo {
    strategy: RwLock<Option<BuddyAllocatorManager>>,
    frame_allocator: Mutex<Option<&'static mut dyn FrameSingleAllocator>>,
    free_frames: Mutex<Option<Vec<PhysAddr>>>,
}
```

To begin with the `strategy` field is `None` so the default (frame) allocator is used. Once we put something in `strategy` that's used instead by the allocator:

```rust
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if_chain! {
            if let Some(ref strategy) = *ALLOCATOR_INFO.strategy.read();
            then {
                return strategy.alloc(layout);
            }
        }
        // else use the frame allocator...
    }
    // same for dealloc
}
```

Finally, we need to construct a `BuddyAllocatorManager` and put it in strategy. This is however a bit tricky: In order to work, the manager will have to have at least one `BuddyAllocator` in it. That's because once we enable the manager as our allocation strategy, if we try to create a new `BuddyAllocator` at that point, the manager won't be able to support the memory allocations that the `BuddyAllocator` needs for its internal structures and the creation will fail. Therefore we need to create first a single `BuddyAllocator` inside the manager! That first one will be used to support the memory allocations in the second one that will be created. Then when we create the third one it can use any of the previous two, etc.

In order to do this, we fetch a single page from the frame allocator and create a `BuddyAllocator` that handles that page in the manager. Then, once we switch our strategy to point to `BuddyAllocatorManager` we can build up its list of allocators (as the more memory an allocator handles, the bigger its internal structures). Eventually, we have enough of them for most of the memory!

This is what becomes of our old `init_global_alloc` method (which was used in part 1 to initialize the `ALLOCATOR_INFO` struct):

```rust
pub fn init_global_alloc(frame_alloc: &'static mut dyn FrameSingleAllocator) {
    let first_page = unsafe { frame_alloc.allocate().unwrap() };
    init_allocator_info(frame_alloc);
    // create our buddy allocator manager (holds a list of buddy allocators for memory regions)
    let manager = BuddyAllocatorManager::new();
    // Create a buddy allocator over a single page which will be provided by our old allocator.
    // This helps us have a single valid page from which our buddy allocator
    // will be able to give blocks away, as otherwise on its first allocation, the buddy allocator
    // would have to call itself in order to create its own internal structures
    // (ie. the free list for each level and the array that holds whether each block is split or not).
    // This way we have one buddy allocator with a single page, which will be used by the second
    // one which will be larger, which will then be used by a larger one until we can map most
    // of the memory. None of these allocators should therefore need to use itself in order to
    // allocate its internal structures which saves us some headaches.
    manager.add_memory_area(first_page, first_page.offset(FRAME_SIZE), 16);
    // Moment of truth! Start using our list of buddy allocators.
    ALLOCATOR_INFO.strategy.write().replace(manager);
    // Create a second, larger buddy allocator in our list which is supported by the first one,
    // as described above.
    let frame_alloc = ALLOCATOR_INFO.frame_allocator.lock().take().unwrap();
    // Get our current buddy allocator
    ALLOCATOR_INFO
        .strategy
        .read()
        .as_ref()
        .map(|buddy_manager| {
            // Allocate increasingly large memory areas.
            // The previously created buddy allocator (which uses a single page) will be used to back
            // the first of these areas' internal structures to avoid the area having to use itself.
            // Then the first two areas will be used to support the third, etc.
            // Until we can support 1GiB buddy allocators (the final type) which need a big
            // amount of continuous backing memory (some MiB for the is_split bitmap plus
            // several Vecs for the free lists).
            buddy_manager.add_mem_area_with_size(frame_alloc, FRAME_SIZE * 8, 16);
            buddy_manager.add_mem_area_with_size(frame_alloc, FRAME_SIZE * 64, 16);
            buddy_manager.add_mem_area_with_size(frame_alloc, 1 << 24, 16);
            while buddy_manager.add_mem_area_with_size(frame_alloc, 1 << 30, 16) {}
        });
}
```

All the magic is in place now, and it works! Every time Rust needs to put something in the heap now, this happens:
* The `alloc` method of the registered `#[global_allocator]` is called (`Allocator` struct)
* That method locks and reads the `strategy` field of the static `ALLOCATOR_INFO` struct
* As `strategy` points to the `BuddyAllocatorManager`, we pass the memory request over to it
* The manager loops through its list of `BuddyAllocator`s and asks the first to allocate some memory
* Each `BuddyAllocator` goes through its free list for the minimum memory size larger than the requested memory size
* If the free list is empty it tries to split a block one level above (and if that free list is empty it goes one level above, etc.)
* If there's no memory available in that allocator, the next one is tried by the manager until one of them allocates the memory
* Else, if none allocate the memory, the request fails and the manager returns `null_mut()` (a.k.a 0)

And with this last list, this series of posts is done! This whole construct was easier than I expected to be honest, plus I didn't expect Rust to bend to my will like that and allow me to do some things that some would consider unsafe. Of course there were a lot of compiler errors on the way, but when writing a kernel that's **MUCH** better than run-time panics!
