---
title: "Rust-OS Kernel buddy allocator - Part 2: Buddy allocator"
tags: rust kernel buddy allocator
---

This relates to my very-much-in-development kernel in Rust: <https://github.com/nikofil/rust-os>

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
