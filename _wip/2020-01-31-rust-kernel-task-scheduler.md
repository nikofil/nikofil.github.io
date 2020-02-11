---
title: "Rust-OS Kernel - Task scheduler"
categories: Kernel Rust Coding
tags: rust kernel userspace
---

This post is about writing a simple, round-robin task scheduler for my Rust kernel. It builds on some concepts I wrote about in my previous post: [To userspace and back!]({% post_url 2020-02-12-rust-kernel-to-userspace-and-back %}).

Source code: <https://github.com/nikofil/rust-os> and in particular [the `scheduler.rs` file](https://github.com/nikofil/rust-os/blob/master/kernel/src/scheduler.rs)

So, we've made it this far. We've managed to jump to userspace and have it call the kernel. That's quite boring though! Our kernel code is still tightly coupled with the user-mode program: It jumps to a specified point in the code, and is called back shortly after. That's why we need a scheduler, so that programs can execute other programs and we have something that resembles a real kernel. Of course we have nothing to execute yet - we'd need files for that, which need a filesystem! That will come later. First, let's make our kernel work with 2 predefined processes.


## Building a Task struct

What is a process? How can we take the processor from executing one process to another, and then back, while giving the processes the illusion they haven't been interrupted at all?

The most important pieces of information that we need to keep about the state of a process at any given time are its registers and memory. Other things might be needed in the future, such as a mapping of file handles in the program to actual files in the filesystem, but we don't even have a filesystem yet!

When we want to swap out the currently executing program and swap in the next one to be executed, the first thing we must do is save the previously executing program's registers. That's because we want to be able to use the registers in our kernel without losing the values the program has stored in them. Otherwise the program could never work if, at any moment, it could be interrupted and its registers changed. The set of all registers that we want to save is called the [task context](https://en.wikipedia.org/wiki/Context_(computing)) and will be the first struct that we have to define, with a field for each register:

```rust
#[derive(Debug, Clone)]
pub struct Context {
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}
```

Upon taking back control from an executing program, saving its context is the first thing we need to do.

Of course, we can't have programs reading each other's memory! Virtual memory is also a part of the context, however we don't need to save anything each time we switch contexts. Why is that? Well, because the virtual memory of a process is defined by the page table that is assigned to that process - this way we can tell apart the memory of multiple processes while they might all see the same virtual addresses. We only define the page table once, when starting the process. Then we hand that process the keys and let it do what it wishes with its virtual memory, and the processor chugs along and translates the virtual addresses to physical. Therefore we don't need to save anything when switching contexts: We know the address of the page table of each process, and we just need to restore that address to the appropriate register (`cr3`) when switching.

Besides these things, a process needs a stack to run. That's where local variables, function parameters and return values are stored. The stack gets no special treatement from the processor: the kernel is responsible for making some room for it in the memory and passing the pointer to the program in the `rsp` register. How do we make that room in the memory? Well, we just allocate an array of bytes! And what is an array of bytes in Rust? Simply a `Vec<u8>`.

We have to keep that `Vec` somewhere, however. We don't want Rust to consider it unused and reclaim the memory before the process is done with it. What better place to keep it than our upcoming Task struct, then?

You might notice a disrepancy: We didn't need to allocate any other memory for the program. At this point the program memory (besides the stack) only contains the program code - but where does that memory come from?

Well, the answer is that we're cheating a bit here: At this point all our userspace program code is simply functions in our kernel. We take their physical address, map it to a virtual address like `0x400000`, jump to it while in ring 3 and call it a day. The compiler makes sure these functions are somewhere in the memory, and it doesn't let anyone mess with that piece of memory. So we don't need to explicitly allocate any memory for the code. We will have to, however, once we want to load arbitrary programs from a filesystem.

But anyway, back to the stack. The stack grows downwards: if you keep pushing variables to it, the `rsp` register which points to the last element in the stack will decrease. Therefore, the initial value of `rsp` will be a pointer to the first byte after the stack space. This is essentially the virtual address to which we mapped the stack, plus the size of the stack. I use a member in the Task struct to keep that address, so that I can set `rsp` when first scheduling the program.

Finally, the program needs to start somewhere. This also depends on what virtual address we map it to. Because we can only map pages and the function is not guaranteed to start on the beginning of a page, the program might not start at the address we map its page to but some bytes later. Therefore I use another member for storing this virtual address so that I can set `rip` (the instruction pointer) to it when first starting the program.

Finally, in all its glory, here is our Task struct!

```rust
struct Task {
    ctx: Option<Context>,
    exec_base: mem::VirtAddr,
    stack_end: mem::VirtAddr,
    _stack_vec: Vec<u8>,
    task_pt: Box<mem::PageTable>,
}
```

## Userspace processes

maybe move that up?
TODO


## Scheduling a process

TODO
    let userspace_fn_1_in_kernel = mem::VirtAddr::new(userspace::userspace_prog_1 as *const () as u64);
    let userspace_fn_2_in_kernel = mem::VirtAddr::new(userspace::userspace_prog_2 as *const () as u64);
    unsafe {
        let sched = &scheduler::SCHEDULER;
        sched.schedule(userspace_fn_1_in_kernel);
        sched.schedule(userspace_fn_2_in_kernel);
        init_pics();
        loop {
            sched.run_next();
        }
 


## Interrupting the running process

TODO
