---
title: "Rust-OS Kernel - Task scheduler"
categories: Kernel Rust Coding
tags: rust kernel userspace
---

TODO

 - the entire scheduler.rs

timer interrupt for rescheduling


+#[naked]
+unsafe extern fn timer(_stack_frame: &mut InterruptStackFrame) {
+    asm!("cli" :::: "intel", "volatile");
+    let ctx = scheduler::get_context();
+    scheduler::SCHEDULER.save_current_context(ctx);
+    end_of_interrupt(32);
+    asm!("sti" :::: "intel", "volatile");
+    // scheduler::restore_context(&*ctx);
+    scheduler::SCHEDULER.run_next();
+}






jmp to userspace



+    let userspace_fn_1_in_kernel = mem::VirtAddr::new(userspace::userspace_prog_1 as *const () as u64);
+    let userspace_fn_2_in_kernel = mem::VirtAddr::new(userspace::userspace_prog_2 as *const () as u64);
+    unsafe {
+        let sched = &scheduler::SCHEDULER;
+        sched.schedule(userspace_fn_1_in_kernel);
+        sched.schedule(userspace_fn_2_in_kernel);
+        init_pics();
+        loop {
+            sched.run_next();
+        }


userspace.rs
