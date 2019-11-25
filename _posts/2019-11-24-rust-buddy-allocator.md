---
title: "Rust-OS Kernel buddy allocator - Part 2: Buddy allocator"
categories: Kernel Rust Coding
tags: rust kernel buddy allocator
---

This is a continuation of my [Rust kernel allocator post]({% post_url 2019-10-24-rust-kernel-allocator %}).

If you're wondering how I managed to get this far without knowing anything about a kernel, my code is based on the excellent blog posts over at <https://os.phil-opp.com>. Mostly the first, lower level edition.

## Wtf is a buddy allocator

I was looking for possible algorithms to implement for my kernel's memory allocation, and this seemed the most fun. The basic idea is simple: Your memory that you're going to be using for allocations a nice, big, power-of-2-sized continuous block. This block can then be divided into two smaller, equal-sized blocks, which can then be divided further. These 2 blocks are called buddies which is what gives the allocator its name. Every time you get a request for some memory, you divide your smallest block into 2 pieces, and then divide one of those 2 pieces, etc. until you have the smallest block possible that can still accommodate that request. Then, when two buddies are freed, you can merge them and get the bigger block back!

For example, let's imagine you have 128 bytes of memory and you get a request for 16 bytes. This is what the process would look like:

```
|                   128                    | (initial memory state)
|------------------------------------------|
|         64          |         64         | (divide 128-block)
|------------------------------------------|
|    32    |    32    |         64         | (divide first 64-block)
|------------------------------------------|
| 16 | 16  |    32    |         64         | (divide first 32-block)
|------------------------------------------|
| xx | 16  |    32    |         64         | (serve first 16-block and mark as used)
```

You then get another request for 32 bytes. You already have a 32-block ready!

```
| xx | 16  |    32    |         64         | (initial memory state)
|------------------------------------------|
| xx | 16  |    xx    |         64         | (serve first 32-block and mark as used)
```

The previous 16 bytes are freed. You can now merge them with their buddy block and make a bigger 32 byte buddy. :)

```
| xx | 16  |    xx    |         64         | (initial memory state)
|------------------------------------------|
| 16 | 16  |    xx    |         64         | (the previous block was freed)
|------------------------------------------|
|    32    |    xx    |         64         | (the two buddies have been merged)
```

Unfortunately the other 32 byte buddy is still allocated, so we can't merge further. But you get the idea.

So why go through all the trouble? Why not just have a list of free memory areas and, when we get a request, return the smallest block where that request fits? Then, on free, append the memory block back to the list? (aka the [SLOB allocator](https://en.wikipedia.org/wiki/SLOB))

The buddy way of doing things has several advantages:
1. It's neat (everybody loves tree-like structures)
2. We can easily merge unused memory areas so that we can then support large allocations (aka little external fragmentation, of course there are pathological cases as with any algorithm)
3. Allocating and freeing things takes logarithmic to the memory size time
4. We need a few internal structures to support it, but not too many
5. All memory blocks will be aligned to the size of the smallest block size (ie. if the smallest block size you split blocks to is 8 bytes, which it should be at minimum, all blocks will be 8 bytes aligned) which might save us some headaches

A problem that comes with this, however, is the following: If I ask for 513 bytes, I get a 1024-byte block back. The other 511 bytes go unused. This is also known as internal fragmentation. A way to combat this would be to use a [slab allocator](https://www.kernel.org/doc/gorman/html/understand/understand011.html) on top of this allocator which would then split up blocks further for more fine-grained control. This is however beyond what I'm trying to do here and I don't mind losing some memory.

## Implementing the buddy system

We need to define some terms before we can proceed:

- A `block` is a contiguous block of memory. It is identified by its level in the buddy allocator and its index in that level. It can be split into two blocks of half the size (1 level below) or be united with its buddy block to make a block of double the size (1 level above).
- A `buddy_block` is relative to another block, and it's the block the other blck could be united with. The buddy of block `i` is the block `i xor 1`, so the blocks 0 and 1 in a level are buddies, and so are 10 and 11 (but not 9 and 10!).
- A `level` is a list of blocks of the same size. A buddy allocator starts off with a single level 0 block which can then be split into two level 1 blocks, and so on. On each level, the first block has index 0, so the blocks 0 and 1 at level 4 if united would generate the block level 0 at level 3 (and vice-versa if split).
- `num_levels` is the number of non-leaf levels for a buddy allocator. If we support levels 0, 1 and 2 (ie. our L0 block can be split into 2 L1 blocks or 4 L2 blocks), our level number would be `2`.
- The `block_size` shall be the size of each block on the leaf level, so the minimum size of a memory block that we can return. One level above that, the blocks will be of size `block_size * 2` and so on.
- A `free_list` for a level is the list of blocks in that level that are not in use.
- `start_addr` is the first physical memory address that a buddy allocator manages.

And some relations:

- `max_size = block_size << num_levels`
- `end_addr = start_addr + max_size`
- `children_of_block(Lx, block_y) = (Lx+1, block_y*2), (Lx+1, block_y*2 + 1)`
- `parent_of_block(Lx, block_y) = (Lx-1, block_y / 2)`
- `size_of_block_at_level(Lx) = max_size >> x`

(where `Lx` is level #x and `block_y` is block #y at that level)

With these terms in mind we can start implementing the buddy allocator! The following struct contains all that we need.

```rust
struct BuddyAllocator {
    start_addr: PhysAddr,
    end_addr: PhysAddr,
    num_levels: u8,
    block_size: u16,
    free_lists: Vec<Vec<u32>>,
}
```

Let's initialize it. To do that, we need to be able to figure out how many levels our allocator will have, given its start and end address. For now we assume that the memory that our allocator handles (the space between the start and end addresses) is a power of 2, which simplifies things. As we said above, `max_size = block_size << num_levels`, so we increase our `num_levels` from 0 until this equation holds true.

Also we initialize our free lists. As the entire memory block is free, we store a `0` at the L0 free list.

```rust
impl BuddyAllocator {
    fn max_size(&self) -> usize {
        // max size that can be supported by this buddy allocator
        (self.block_size as usize) << (self.num_levels as usize)
    }

    fn new(start_addr: PhysAddr, end_addr: PhysAddr, block_size: u16) -> BuddyAllocator {
        // number of levels excluding the leaf level
        let mut num_levels: u8 = 0;
        while ((block_size as u64) << num_levels as u64) < end_addr.addr() - start_addr.addr() {
            num_levels += 1;
        }
        // vector of free lists
        let mut free_lists: Vec<Vec<u32>> = Vec::with_capacity((num_levels + 1) as usize);
        // Initialize each free list with a small capacity (in order to use the current allocator
        // at least for the first few items and not the one that will be in use when we're actually
        // using this as the allocator as this might lead to this allocator using itself and locking)
        for _ in 0..(num_levels + 1) {
            free_lists.push(Vec::with_capacity(4));
        }
        // The top-most block is (the only) free for now!
        free_lists[0].push(0);
        // We need 1<<levels bits to store which blocks are split (so 1<<(levels-3) bytes)
        BuddyAllocator {
            start_addr,
            end_addr,
            num_levels,
            block_size,
            free_lists,
        }
    }

    fn contains(&self, addr: PhysAddr) -> bool {
        // whether a given physical address belongs to this allocator
        addr.addr() >= self.start_addr.addr() && addr.addr() < self.end_addr.addr()
    }
}
```

Next we tackle the "difficult" part: Allocating a memory block.

First, let's find which memory level we need to use to serve a request for `size` bytes. We start from level 0 and go up the levels until we reach a level that can't accommodate the request. Then, we go one level back, and we have the level where the request should go.

```rust
impl BuddyAllocator {
    fn req_size_to_level(&self, size: usize) -> Option<usize> {
        // Find the level of this allocator than can accommodate the required memory size.
        let max_size = self.max_size();
        if size > max_size {
            // can't allocate more than the maximum size for this allocator!
            None
        } else {
            // find the largest block level that can support this size
            let mut next_level = 1;
            while (max_size >> next_level) >= size {
                next_level += 1;
            }
            // ...but not larger than the max level!
            let req_level = cmp::min(next_level - 1, self.num_levels as usize);
            Some(req_level)
        }
    }
}
```

With that settled, let's make a method that gives us a block number back from a level. In the easy case, we have a free block at that level. In the hard case, we need to go up a level and split a block (which might require us to go up another level to split an even larger block).

```rust
impl BuddyAllocator {
    fn get_free_block(&mut self, level: usize) -> Option<u32> {
        // Get a block from the free list at this level or split a block above and
        // return one of the splitted blocks.
        self.free_lists[level]
            .pop()
            .or_else(|| self.split_level(level))
    }

    fn split_level(&mut self, level: usize) -> Option<u32> {
        // We reached the maximum level, we can't split anymore! We can't support this allocation.
        if level == 0 {
            None
        } else {
            self.get_free_block(level - 1).map(|block| {
                // Get a block from 1 level above us and split it.
                // We push the second of the splitted blocks to the current free list
                // and we return the other one as we now have a block for this allocation!
                self.free_lists[level].push(block * 2 + 1);
                block * 2
            })
        }
    }
}
```

We can finally make an allocation. As a block of size `n` will always be `n`-bytes aligned, if the alignment is larger than the size requested for some reason, we use that as the size. Then we find which level can accommodate the memory request, we get a block from that level and we calculate the physical address of that block. That's simply: `start_addr + block_idx * size_of_block_at_level(Lx)` (`Lx` being the level that served the request, and `block_idx` the number of the returned block)

```rust
impl BuddyAllocator {
    fn alloc(&mut self, size: usize, alignment: usize) -> Option<PhysAddr> {
        // We should always be aligned due to how the buddy allocator works
        // (everything will be aligned to block_size bytes).
        // If we need in some case that we are aligned to a greater size,
        // allocate a memory block of (alignment) bytes.
        let size = cmp::max(size, alignment);
        // find which level of this allocator can accommodate this amount of memory (if any)
        self.req_size_to_level(size).and_then(|req_level| {
            // We can accommodate it! Now to check if we actually have / can make a free block
            // or we're too full.
            self.get_free_block(req_level).map(|block| {
                // We got a free block!
                // get_free_block gives us the index of the block in the given level
                // so we need to find the size of each block in that level and multiply by the index
                // to get the offset of the memory that was allocated.
                let offset = block as u64 * (self.max_size() >> req_level as usize) as u64;
                // Add the base address of this buddy allocator's block and return
                PhysAddr::new(self.start_addr.addr() + offset)
            })
        })
    }
}
```

Before deallocating a block, we first need a way to merge two buddy blocks, given the index of one of them. First we check if the buddy block of the one given block is in the free list. If so, we pop both of them (I assume that the current block is the one in the end of the list so we use `pop` for that as this hold for my implementation) and we push the parent block one level above. Finally try doing the same process on the above level in case we can merge further.

```rust
impl BuddyAllocator {
    fn merge_buddies(&mut self, level: usize, block_num: u32) {
        // toggle last bit to get buddy block
        let buddy_block = block_num ^ 1;
        // if buddy block in free list
        if let Some(buddy_idx) = self.free_lists[level]
            .iter()
            .position(|blk| *blk == buddy_block)
        {
            // remove current block (in last place)
            self.free_lists[level].pop();
            // remove buddy block
            self.free_lists[level].remove(buddy_idx);
            // add free block to free list 1 level above
            self.free_lists[level - 1].push(block_num / 2);
            // repeat the process!
            self.merge_buddies(level - 1, block_num / 2)
        }
    }
}
```

Finally deallocation: Find which level was used for the given size and alignment (thanks for providing these, Rust!) and which block was used based on the physical address (the opposite of the procedure above). Finally, push the block index to the appropriate free list and try to merge it with its buddy block using the method we just defined.

```rust
impl BuddyAllocator {
    fn dealloc(&mut self, addr: PhysAddr, size: usize, alignment: usize) {
        // As above, find which size was used for this allocation so that we can find the level
        // that gave us this memory block.
        let size = cmp::max(size, alignment);
        // find which level of this allocator was used for this memory request
        if let Some(req_level) = self.req_size_to_level(size) {
            // find size of each block at this level
            let level_block_size = self.max_size() >> req_level;
            // calculate which # block was just freed by using the start address and block size
            let block_num =
                ((addr.addr() - self.start_addr.addr()) as usize / level_block_size) as u32;
            // push freed block to the free list so we can reuse it
            self.free_lists[req_level].push(block_num);
            // try merging buddy blocks now that we might have some to merge
            self.merge_buddies(req_level, block_num);
        }
    }
}
```

That was easy enough! Now we just need to be able to construct one of these (or more)...

## Constructing buddy allocators in a sort of sane manner

// TODO
