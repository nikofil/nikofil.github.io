---
title: "Rust-OS Kernel - To userspace and back!"
categories: Kernel Rust Coding
tags: rust kernel userspace
---

This post documents my attempts to manage to jump (or return?) from kernel-space to usermode in my Rust kernel so that it can do what a kernel is supposed to actually do: give the CPU to user programs. That's pretty exciting! In the next part, we'll even take control back from the programs so that we can implement a scheduler.

Source code: <https://github.com/nikofil/rust-os>


## What the hell is a usermode?

When we are running a program in usermode in a real kernel, life is pretty easy: We don't need to worry about crashing the entire system, we can pretend the entire [virtual memory space belongs to us](https://wiki.osdev.org/Memory_Management#Virtual_Address_Space) and we don't need to care about [the GDT and segments](https://wiki.osdev.org/GDT_Tutorial). If we need to interact with the rest of the world, we can simply [perform a syscall to the kernel to do it for us](https://wiki.osdev.org/System_Calls) as we are powerless to do so.

That's because in usermode a program is limited to only doing processing of data. It can't communicate with devices, access important registers (ie. Control Registers, such the CR3 used to set up paging tables) or read memory that is on a higher access level. It has to ask the kernel for even the simplest task, such as reading or writing a single character from/to the input/screen. Without doing that, no usermode program could ever have inputs or outputs of any kind.

The kernel, of course, has to do all the heavy lifting: It has to set up the environment just perfect for the user program to have all of its information where it expects in order to be able to run. Then, when the user program performs a syscall, it has to make sure to save all of its registers and stack location to be able to restore it later so that a syscall behaves just like a regular call from the program's perspective, while in reality it's a much more complex process.

Whenever the kernel wants to give execution to a user program, the process can be summarized into 3 steps:
* Enable the page table that has this program's memory mapped to the correct virtual addresses (as each program might be using the same virtual address, but different physical memory underneath)
* Set the `cs` and `ds` registers to the proper indexes in the GDT to indicate that we're currently in Ring3 (usermode)
* Set all the appropriate registers and perform an `iretq` (or `sysretq` if returning from a syscall)

On the other hand, calling the kernel from usermode is simply a matter of setting the registers to the desired syscall number and parameters and performing a `syscall` instruction, upon which the kernel has to handle the messy part again.

Let's look at each one of these steps.


## Enabling the page table for the user process

The [page table](https://wiki.osdev.org/Page_Tables) is a structure that allows the kernel to use virtual paging. That means that, when the processor is in [long mode](https://wiki.osdev.org/X86-64#Long_Mode) the memory addresses almost never correspond to the physical memory address that is used. Instead, the page table is used to lookup which physical page a virtual page corresponds to whenever we store to or load from an address, except for a few special operations. One of these special operations is, of course, setting the register that determines where the page table is: `CR3`. This register must know the physical location of the (topmost) page table, as otherwise it would have to use itself to resolve the physical location which would be even more confusing!

Of course this subject goes quite deeper, with nested page tables and permissions, but I won't go that deep into that here.

Okay, so our first task is to create a page table for our new user process. We still want to keep the kernel mapped where it's already loaded, as otherwise the next instruction after loading the page table would (probably) not be there and we would crash. So first order of business is to copy the kernel's PT entries over to a new one:

```rust
impl PageTable {
    pub unsafe fn new() -> Box<PageTable> {
        let mut pt = Box::new(PageTable{ entries: [PTEntry(0); 512] });
        pt.entries[0].set_phys_addr(Self::alloc_page());
        pt.entries[0].set_bit(BIT_PRESENT, true);
        pt.entries[0].set_bit(BIT_WRITABLE, true);
        pt.entries[0].set_bit(BIT_USER, true);
        let mut pt0 = pt.entries[0].next_pt();
        let cur_pt0 = get_page_table().entries[0].next_pt();
        pt0.entries[3] = cur_pt0.entries[3].clone();
        pt0.entries[4] = cur_pt0.entries[4].clone();
        pt0.entries[5] = cur_pt0.entries[5].clone();
        pt0.entries[6] = cur_pt0.entries[6].clone();
        pt
    }
}
```

What this code does is that it creates a new page table structure which maps the virtual addresses 0xC0000000 to 0x1C0000000 to the same physical memory that the kernel's page table maps these addresses to. This is exactly 4GiB that the kernel uses not only for its own code, but to also have the entire memory mapped. This means the kernel (and only the kernel) can access physical address `x` by accessing virtual address `0xC0000000 + x` which makes the transition pretty easy. The kernel itself is located pretty early in that memory.

We also allow the page table to be user accessible and writable. This doesn't mean that necessarily all the virtual addresses that it maps will be writable and user-accessible, as each entry in the page table at this level points to another page table. In these other page tables then we can restrict the write or user-accessible bits as needed.

Great, so we allocated the topmost page table and we have a pointer to it! What do we do with this thing?

We still have to map the virtual memory for the program's code and stack to physical memory. But first we have to know the physical address where our program begins, in order to be able to map a virtual address to it!

For simplicity's (ha) sake, my current usermode program is simply another Rust function. It doesn't have anything to do for now:

```rust
pub unsafe fn userspace_prog_1() {
    asm!("\
        nop
    ":::: "intel");
}
```

We now have to determine its physical address, and where the physical page that contains it is located (as page tables deal in units of, well, pages). Then we map that page to `0x400000` which is a pretty common place for a program's entry point (or at least it was in the 32-bit days). It's also an address that makes me excited, as it was the first address you used to see when debugging a new program!

```rust
let userspace_fn_1_in_kernel = mem::VirtAddr::new(userspace::userspace_prog_1 as *const () as u64);
let userspace_fn_phys = userspace_fn_1_in_kernel.to_phys().unwrap().0; // virtual address to physical
let page_phys_start = (userspace_fn_phys.addr() >> 12) << 12; // zero out page offset to get which page we should map
let fn_page_offset = userspace_fn_phys.addr() - page_phys_start; // offset of function from page start
let userspace_fn_virt_base = 0x400000; // target virtual address of page
let userspace_fn_virt = userspace_fn_virt_base + fn_page_offset; // target virtual address of function
serial_println!("Mapping {:x} to {:x}", page_phys_start, userspace_fn_virt_base);
let mut task_pt = mem::PageTable::new(); // copy over the kernel's page tables
task_pt.map_virt_to_phys(
    mem::VirtAddr::new(userspace_fn_virt_base),
    mem::PhysAddr::new(page_phys_start),
    mem::BIT_PRESENT | mem::BIT_USER); // map the program's code
task_pt.map_virt_to_phys(
    mem::VirtAddr::new(userspace_fn_virt_base).offset(0x1000),
    mem::PhysAddr::new(page_phys_start).offset(0x1000),
    mem::BIT_PRESENT | mem::BIT_USER); // also map another page to be sure we got the entire function in
let mut stack_space: Vec<u8> = Vec::with_capacity(0x1000); // allocate some memory to use for the stack
let stack_space_phys = mem::VirtAddr::new(stack_space.as_mut_ptr() as *const u8 as u64).to_phys().unwrap().0;
// take physical address of stack
task_pt.map_virt_to_phys(
    mem::VirtAddr::new(0x800000),
    stack_space_phys,
    mem::BIT_PRESENT | mem::BIT_WRITABLE | mem::BIT_USER); // map the stack memory to 0x800000
```

We can now enable this page table! That's simply a matter of calling `task_pt.enable()` which does the following:

```rust
pub unsafe fn enable(&self) {
    let phys_addr = self.phys_addr().addr();
    asm!("mov $0, %cr3" :: "{rax}"(phys_addr) :: "volatile");
}
```

`cr3` is now set! The virtual memory above `0xC0000000` will be exactly the same, but there's now memory mapped to `0x400000` and `0x800000`!


## Setting the GDT entries and MSR registers

The way segment registers (`cs`, `ds`, `ss` etc.) work in protected and long mode is that they are set to an index in the structure called the [Global Descriptor Table (GDT)](https://wiki.osdev.org/Global_Descriptor_Table), which contains entries for each memory segment we might want to use. These registers were used to solve the problem of accessing different memory regions by early x86 processors before paging was a thing. The way it worked was roughly that each segment started at a specified physical memory address, so instead of using a page table and a virtual address to access the memory you wanted you would use a segment for the base of the so-called linear address and an offset to access the specific value that you wanted. This underwent some changes with the introduction of [protected mode](https://wiki.osdev.org/Protected_Mode) which allowed processors to use paging. Nowadays processors are backwards compatible and usually when booting go through real and protected mode before entering 64-bit long mode which allows us to use (currently) 48 bits for addressing. This is a lot more than the 16 bits segment base plus 16 bits offset that we could use in the segmentation days: using 48 bits we can address up to 256 TiB of memory. Segments are therefore mostly obsolete nowadays: In fact, most of the segment bases are ignored and are forced to be 0 (besides `fs` and `gs` which can have nonzero base addresses).

Why do we care about them, then? That's because segments also define the current privilege level that the processor is in. These privilege levels are also called rings, as each ring has all the privileges of the rings below it so if you visualize it, ring 0 would contain ring 1, which would contain ring 2 etc. Usually only two rings are used: Ring 0 for the kernel and ring 3 for user-space programs. In ring 0 the processor can interact with physical hardware using special instructions, as well as do things like change the loaded page table which would be disastrous if any user-space program could do.

For each instruction, there are 3 privilege levels we must consider to know if it will throw a [General Protection Fault](https://wiki.osdev.org/Exceptions#General_Protection_Fault):

* The **CPL** is the current level and is defined by the last 2 bits of the `cs` register (so it can take values of 0 to 3)
* The **DPL** is the descriptor level. It is the minimum CPL that is allowed to access that segment and is stored in the GDT entry that each segment register points to. If `DPL > CPL` and the memory segment defined by that entry is attempted to be accessed, you get a GPF!
* The **RPL** is the requested level and is defined by the last 2 bits of other segment registers. It works the same way that the DPL does but is stored in the register instead of the entry that it points to. I believe that it's obsolete as it does the same job as the DPL but is kept around for backwards compatibility. Again, RPL > CPL causes a GPF!

If you've followed the tutorial at <https://os.phil-opp.com/double-fault-exceptions/> you should already have a working GDT structure. We'll now have to modify that, in order to include entries for both kernel and user-mode segments. Also, for reasons that I'll explain soon, these entries have to be in a very particular order. This is the way my GDT looks:

```rust
lazy_static! {
    static ref GDT: (GlobalDescriptorTable, [SegmentSelector; 5]) = {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_data_flags = DescriptorFlags::USER_SEGMENT | DescriptorFlags::PRESENT | DescriptorFlags::WRITABLE;
        let code_sel = gdt.add_entry(Descriptor::kernel_code_segment());
        let data_sel = gdt.add_entry(Descriptor::UserSegment(kernel_data_flags.bits()));
        let tss_sel = gdt.add_entry(Descriptor::tss_segment(&TSS));
        let user_data_sel = gdt.add_entry(Descriptor::user_data_segment());
        let user_code_sel = gdt.add_entry(Descriptor::user_code_segment());
        (gdt, [code_sel, data_sel, tss_sel, user_data_sel, user_code_sel])
    };
}

pub fn init_gdt() {
    GDT.0.load();
    let stack = unsafe { &STACK as *const _ };
    let user_stack = unsafe { &PRIV_TSS_STACK as *const _ };
    println!(
        " - Loaded GDT: {:p} TSS: {:p} Stack {:p} User stack: {:p} CS segment: {} TSS segment: {}",
        &GDT.0 as *const _, &*TSS as *const _, stack, user_stack, GDT.1[0].0, GDT.1[1].0
    );
    unsafe {
        set_cs(GDT.1[0]);
        load_ds(GDT.1[1]);
        load_tss(GDT.1[2]);
    }
}
```

We see that the kernel-mode segment registers are loaded upon initialization of the kernel! In a similar fashion, we will be setting the user-mode ones before jumping to user-mode for the first time to restrict the user program's permissions. How do we restore the kernel-mode ones afterwards, though?

Finally, the last piece of the puzzle: Once we are in user-mode and we want to make a syscall we need a way to restore our old segment registers so that we have full permissions again. Obviously this is not something the user program can do, and a special mechanism is once again needed. As I want to use the modern syscall / sysret instructions to interface with the kernel, there are some model-specific register (MSRs) that need to be defined. The first of these is called `IA32_STAR` and its purpose is exactly what we want: Upon a syscall, `cs` and `ss` are restored by using the value stored in that register. Specifically, the following happens upon executing the [syscall instruction](https://www.felixcloutier.com/x86/syscall), among other things:

```
CS.Selector ← IA32_STAR[47:32] AND FFFCH (* Operating system provides CS; RPL forced to 0 *)
SS.Selector ← IA32_STAR[47:32] + 8;
```

Side note: Thanks to <https://www.felixcloutier.com/x86/> for providing these invaluable details for each instruction!

In a similar manner, the following happens upon returning from a syscall, using the [sysret instruction](https://www.felixcloutier.com/x86/sysret):

```
CS.Selector ← IA32_STAR[63:48]+16;
SS.Selector ← (IA32_STAR[63:48]+8) OR 3;
```

The spec of these two instructions therefore doesn't give us too much wiggle room. We have to setup `IA32_STAR` so that bits 32:47 contain the index of the kernel-mode code segment entry in the GDT, and the user-mode stack segment entry (for which we'll use the data entry, as it makes no difference) has to be right after that. Similarly bits 48:63 will contain the index of the user-mode code segment entry in the GDT, after which will be the index of the user-mode data segment entry. That's a mouthfull, so let's get to it and forget about this part forever afterwards!

Each entry in the GDT is normally 8 bytes, however the TSS one is special and takes up two entries, being 16 bytes. Also the first entry has to be empty, so we don't consider it. This is what our GDT looks like:

| Offset    | Entry         | IA32_STAR bits |
| --------- | ------------- | -------------- |
| +0        | Empty         |                |
| +8        | Kernel code   | 32:47          |
| +16       | Kernel data   |                |
| +24       | TSS pt1       |                |
| +32       | TSS pt2       | 48:63          |
| +40       | User data     |                |
| +48       | User code     |                |

This way, the upon syscall/sysret the segment registers will point to the entries we want! For syscall we want `IA32_STAR[32:47] == 8` The sysret one in particular is rather confusing: Notice that it has nothing to do with the TSS register. What we want is for `IA32_STAR[48:63] + 8 == user SS` and `IA32_STAR[48:63] + 16 == user CS` which we get by putting the offset 32 (=0x20) in that position in the register. Notice that the last 2 bits of the segment selector however need to be 3 here to indicate that we are in ring 3, so we finally use the value 0x23 for that position in the register.

All in all, we want the register to have the value `0x23000800000000`. We set that register with the instruction `wrmsr` (write model-specific register). The higher bits are set to the value of `rdx` and the lower (which should be zero) to the value of `rax` while `rcx` determines which MSR we write to (`IA32_STAR` is `0xC0000081`). The following code does what we want:

```rust
// register for address of syscall handler
const MSR_STAR: usize = 0xC0000081;

pub unsafe fn init_syscalls() {
    // write segments to use on syscall/sysret to AMD'S MSR_STAR register
    asm!("\
    xor rax, rax
    mov rdx, 0x230008 // use seg selectors 8, 16 for syscall and 43, 51 for sysret
    wrmsr" :: "{rcx}"(MSR_STAR) : "rax", "rdx" : "intel", "volatile");
}
```

Finally we have to enable System Call Extensions (SCE) to be able to use the syscall/sysret opcodes by setting the last bit in the MSR `IA32_EFER`. The following code which I've put in the boot sequence does that:

```asm
mov ecx, 0xC0000080
rdmsr
or eax, 1
wrmsr
```

We're finally done with the GDT part. Phew!


## iretq syscall sysret

TODO

msr registers for mask and syscall addr
setting of segments
