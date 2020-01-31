---
title: "Rust-OS Kernel - To userspace and back!"
categories: Kernel Rust Coding
tags: rust kernel userspace
---

This post documents my attempts to manage to jump (or return?) from kernel-space to usermode in my Rust kernel so that it can do what a kernel is supposed to actually do: give the CPU to user programs. That's pretty exciting! In the next part, we'll even take control back from the programs so that we can implement a scheduler.


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


## GDT

Next we have to have the segment registers set to indicate that we're now in usermode.

TODO


the GDT bit:


+        tss.privilege_stack_table[0] = {
+            let stack_start = VirtAddr::from_ptr(unsafe { &PRIV_TSS_STACK });
+            let stack_end = stack_start + STACK_SIZE;
+            stack_end
+        };



 lazy_static! {
-    static ref GDT: (GlobalDescriptorTable, [SegmentSelector; 2]) = {
+    static ref GDT: (GlobalDescriptorTable, [SegmentSelector; 5]) = {
         let mut gdt = GlobalDescriptorTable::new();
+        let kernel_data_flags = DescriptorFlags::USER_SEGMENT | DescriptorFlags::PRESENT | DescriptorFlags::WRITABLE;
         let code_sel = gdt.add_entry(Descriptor::kernel_code_segment());
+        let data_sel = gdt.add_entry(Descriptor::UserSegment(kernel_data_flags.bits()));
         let tss_sel = gdt.add_entry(Descriptor::tss_segment(&TSS));
-        (gdt, [code_sel, tss_sel])
+        let user_data_sel = gdt.add_entry(Descriptor::user_data_segment());
+        let user_code_sel = gdt.add_entry(Descriptor::user_code_segment());
+        (gdt, [code_sel, data_sel, tss_sel, user_data_sel, user_code_sel])
     };
 }



pub fn init_gdt() {
     GDT.0.load();
     let stack = unsafe { &STACK as *const _ };
+    let user_stack = unsafe { &PRIV_TSS_STACK as *const _ };
     println!(
-        " - Loaded GDT: {:p} TSS: {:p} Stack {:p} CS segment: {} TSS segment: {}",
-        &GDT.0 as *const _, &*TSS as *const _, stack, GDT.1[0].0, GDT.1[1].0
+        " - Loaded GDT: {:p} TSS: {:p} Stack {:p} User stack: {:p} CS segment: {} TSS segment: {}",
+        &GDT.0 as *const _, &*TSS as *const _, stack, user_stack, GDT.1[0].0, GDT.1[1].0
     );
     unsafe {
         set_cs(GDT.1[0]);
-        load_tss(GDT.1[1]);
+        load_ds(GDT.1[1]);
+        load_tss(GDT.1[2]);
     }
 }
+
+#[inline(always)]
+pub unsafe fn set_usermode_segs() -> (u16, u16) {
+    // set ds and tss, return cs and ds
+    let (mut cs, mut ds, mut tss) = (GDT.1[4], GDT.1[3], GDT.1[2]);
+    cs.0 |= PrivilegeLevel::Ring3 as u16;
+    ds.0 |= PrivilegeLevel::Ring3 as u16;
+    tss.0 |= PrivilegeLevel::Ring3 as u16;
+    load_ds(ds);
+    // load_tss(tss);
+    (cs.0, ds.0)
+}


## iretq syscall sysret

TODO

enable System Call Extensions (SCE) to be able to use the syscall opcode

     rdmsr
     or eax, 1
     wrmsr


links to instruction workings
