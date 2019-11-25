---
title: "Fixing the Dell XPS 13's double space issue (with Linux kernel modules!)"
categories: Kernel C
tags: kernel c drivers
---
Some days ago I bought the Dell XPS 13 9350. One of the most popular laptops, still quite expensive two years after its launch. While setting it up, I soon found out about a very distracting issue: The space key would occasionally produce two spaces instead of one, and it happened usually when typing fast. It didn't occur very often, but it was still quite annoying when it did, and it wasn't what I expected from a machine of that price tag and fame.

I managed to find a way to reproduce it often (essentially just hit a lot of keys fast), and I took it back to the store the next day. Eventually I got a replacement that seemed to work alright while I was testing it. Until it didn't and the same issue popped up.

At this point I knew a replacement wouldn't work, a refund wasn't possible, and I didn't want to choose another laptop model either (because these bezels). I started looking into software solutions and I found other people with similar issues and some possible software fixes. However all of them didn't do exactly what I wanted, and the ones that possibly did were too ugly and probably slow.

I decided to try and solve the problem myself. Since I was looking for a software solution for a hardware problem, I thought the best thing to do would be to go as low as possible, and catch the error in the keyboard driver itself. It seemed like, strangely, messing with the kernel was the most efficient, easy and fun way to do things, all at once.

## Finding the driver

The first thing to do would be, of course, to find the kernel module responsible for this mess. In order to do that, we first list our input devices and see what we can find.

```bash
$ xinput list
⎡ Virtual core pointer                     id=2 [master pointer  (3)]
⎜   ↳ Virtual core XTEST pointer               id=4 [slave  pointer  (2)]
⎜   ↳ DLL0704:01 06CB:76AE Touchpad            id=11 [slave  pointer  (2)]
⎣ Virtual core keyboard                    id=3 [master keyboard (2)]
    ↳ Virtual core XTEST keyboard              id=5 [slave  keyboard (3)]
    ↳ Power Button                             id=6 [slave  keyboard (3)]
    ↳ Video Bus                                id=7 [slave  keyboard (3)]
    ↳ Power Button                             id=8 [slave  keyboard (3)]
    ↳ Sleep Button                             id=9 [slave  keyboard (3)]
    ↳ Integrated_Webcam_HD                     id=10 [slave  keyboard (3)]
    ↳ Intel HID events                         id=12 [slave  keyboard (3)]
    ↳ Dell WMI hotkeys                         id=15 [slave  keyboard (3)]
    ↳ AT Translated Set 2 keyboard             id=13 [slave  keyboard (3)]
```

As I had no idea how to proceed at this point, I just Googled the most relevant looking things. It turns out, the "AT Translated Set 2 keyboard" which is, well, the laptop keyboard, is handled by a module named `atkbd.ko`.

Linux has this handy utility that lists modules for you called `lsmod`. I was expecting that, if I am right, my module should be there.

```bash
$ lsmod | ack atkbd
$ 
```

But no, it was not listed as a module. After some more looking around, I confirmed what I had feared: The module I was looking for was not a module, and it was instead built in into the kernel.

```bash
$ ack atkbd /lib/modules/4.10.0-19-generic/modules.builtin
kernel/drivers/input/keyboard/atkbd.ko
```

## Changing the driver code

This meant I had no easy way to change the module with my own, to unload it or replace it. That is because the driver code resides in the kernel itself, and not in a separate .ko file that you can load and unload, unlike modules. Fortunately you can change this by downloading and compiling your own kernel with this particular keyboard driver set to module instead of the default built-in in the kernel config. I was not feeling very comfortable messing with the kernel at this level, but I was already determined to get this to work.

I decided to go for linux v4.10.12, not the latest version but a stable one. I copied the configuration my current build was using into the directory, and using the helpful `make menuconfig` command, I changed the driver to be loaded as a module. I started the compilation using all of the processing power of my new laptop for about an hour or so before the new kernel was ready. Running `update-grub2` finalizes the process, and I can confirm everything works by rebooting the laptop into its new kernel. And finally, inside the new kernel, some progress is made.

```bash
~/w/linux-stable :tags/v4.10.12^0 $ lsmod | ack atkbd                     
atkbd                  32768  0
```

Unloading the module with modprobe, I can confirm my keyboard is no longer working, which is actually a good thing. After shutting down the computer through an agonizing long press of the power button (as, well, they keyboard isn't working and I don't have a way to shut down with the mouse thanks to my window manager setup) I am ready to mess with the module.

Inside the Linux kernel repository, find tells me the module source code is located at `./drivers/input/keyboard/atkbd.c`. Looking through the source code, there seem to be some helpful debug messages, which however aren't printed in the system log.

```c
  case ATKBD_RET_NAK:
  if (printk_ratelimit())
   dev_warn(&serio->dev,
     "Spurious %s on %s. "
     "Some program might be trying to access hardware directly.\n",
     data == ATKBD_RET_ACK ? "ACK" : "NAK", serio->phys);
  goto out;
 case ATKBD_RET_ERR:
  atkbd->err_count++;
  dev_dbg(&serio->dev, "Keyboard on %s reports too many keys pressed.\n",
   serio->phys);
  goto out;
```

Turning these on would be a nice start. Once again, Google tells me I should recompile the module with `#define DEBUG 1` on the top in order to enable the `dev_dbg` messages. Compiling the module is done using make. Then we can unload the normal module and load our own, with debug enabled.


```bash
~/w/linux-stable $ make drivers/input/keyboard/atkbd.ko
  CHK     include/config/kernel.release
  CHK     include/generated/uapi/linux/version.h
  CHK     include/generated/utsrelease.h
  CHK     include/generated/timeconst.h
  CHK     include/generated/bounds.h
  CHK     include/generated/asm-offsets.h
  CALL    scripts/checksyscalls.sh
  CC [M]  drivers/input/keyboard/atkbd.o
  MODPOST 4935 modules
  CC      drivers/input/keyboard/atkbd.mod.o
  LD [M]  drivers/input/keyboard/atkbd.ko
~/w/linux-stable $ sudo insmod drivers/input/keyboard/atkbd.ko
insmod: ERROR: could not insert module drivers/input/keyboard/atkbd.ko: File exists
~/w/linux-stable $ sudo modprobe -r atkbd && sudo insmod drivers/input/keyboard/atkbd.ko
~/w/linux-stable $ tail /var/log/syslog
Apr 25 21:15:05 home kernel: [ 3581.762669] atkbd serio0: Received e0 flags 00
Apr 25 21:15:05 home kernel: [ 3581.764112] atkbd serio0: Received 48 flags 00
Apr 25 21:15:05 home kernel: [ 3581.823688] atkbd serio0: Received e0 flags 00
Apr 25 21:15:05 home kernel: [ 3581.823771] atkbd serio0: Received c8 flags 00
Apr 25 21:15:05 home kernel: [ 3581.903077] atkbd serio0: Received e0 flags 00
Apr 25 21:15:05 home kernel: [ 3581.904453] atkbd serio0: Received 48 flags 00
Apr 25 21:15:05 home kernel: [ 3581.982325] atkbd serio0: Received e0 flags 00
Apr 25 21:15:05 home kernel: [ 3581.982426] atkbd serio0: Received c8 flags 00
Apr 25 21:15:06 home kernel: [ 3583.126182] atkbd serio0: Received 1c flags 00
Apr 25 21:15:06 home kernel: [ 3583.161313] atkbd serio0: Received 9c flags 00
```

Now that I know that I'm in the right direction, I can look for a location to add my code. Eventually I spot the most important-looking function in the code.


```c
 /*
 * atkbd_interrupt(). Here takes place processing of data received from
 * the keyboard into events.
 */

static irqreturn_t atkbd_interrupt(struct serio *serio, unsigned char data,
       unsigned int flags)
```

No better place to catch some double spaces that the interrupt handler itself! It seems that the double space happens instantly, so the handler probably receives two key presses very rapidly. Since we are in the kernel, we might as well use the native time unit, which is jiffies, aka clock ticks. At first, I change the driver to output the current number of jiffies elapsed since boot for each keypress in order to see what would be a good threshold to set. Then I start typing away, trying to reproduce the double space while looking at the debug messages produced. I look only for events with data 0x39 and 0xb9, which are my space key's button down and up respectively. After a while I manage to see the issue in the syslog.

```bash
 ~/w/linux-stable $ tail -f /var/log/syslog | ack "Received (39|b9)"
Apr 25 20:56:24 home kernel: [ 2460.648522] atkbd serio0: Received 39 flags 00 current jiffies 4295507460
Apr 25 20:56:24 home kernel: [ 2460.651414] atkbd serio0: Received b9 flags 00 current jiffies 4295507460
Apr 25 20:56:24 home kernel: [ 2460.674950] atkbd serio0: Received 39 flags 00 current jiffies 4295507466
Apr 25 20:56:24 home kernel: [ 2460.706711] atkbd serio0: Received b9 flags 00 current jiffies 4295507474
```

The computer sees two different key presses, with only 6 jiffies difference. This is way too fast to be done normally, as the best I can do by hand by spamming the space key is around 30 jiffies. I decide setting 20 jiffies as the threshold is a good value for now. If two space presses come in less than that, I ignore them.

Holding down the space button also produces a lot of fast space key downs, but no key ups, so I also require there to have been a space key up before blocking the new space key down in order to avoid blocking a long space press. This is the code diff in total:


```diff
 diff --git a/drivers/input/keyboard/atkbd.c b/drivers/input/keyboard/atkbd.c
index ad7395194a2f..f10a2c90787b 100644
--- a/drivers/input/keyboard/atkbd.c
+++ b/drivers/input/keyboard/atkbd.c
@@ -373,6 +373,7 @@ static unsigned int atkbd_compat_scancode(struct atkbd *atkbd, unsigned int code
 static irqreturn_t atkbd_interrupt(struct serio *serio, unsigned char data,
                                   unsigned int flags)
 {
+       static long unsigned int last_space = 0, last_space_up = 0;
        struct atkbd *atkbd = serio_get_drvdata(serio);
        struct input_dev *dev = atkbd->dev;
        unsigned int code = data;
@@ -380,7 +381,16 @@ static irqreturn_t atkbd_interrupt(struct serio *serio, unsigned char data,
        int value;
        unsigned short keycode;
 
-       dev_dbg(&serio->dev, "Received %02x flags %02x\n", data, flags);
+       dev_dbg(&serio->dev, "Received %02x flags %02x current jiffies %lu last space at %lu\n", data, flags, jiffies, last_space);
+       if (data == 0x39) {
+               if (last_space_up >= last_space && jiffies - last_space < 20) {
+                       dev_dbg(&serio->dev, "Detected double space");
+                       goto out;
+               }
+               last_space = jiffies;
+       } else if (data == 0xb9) {
+               last_space_up = jiffies;
+       }
 
 #if !defined(__i386__) && !defined (__x86_64__)
        if ((flags & (SERIO_FRAME | SERIO_PARITY)) && (~flags & SERIO_TIMEOUT) && !atkbd->resend && atkbd->write) {
```

Short and sweet, and it seems to work so far. Of course I wish I didn't have to do this, but at least some fun was had.

## Persisting the changes

In order to have the new driver run on every boot, we have to overwrite the old one. Also, we have to update the initramfs.

```bash
~/w/linux-stable $ sudo cp drivers/input/keyboard/atkbd.ko /lib/modules/4.10.12/kernel/drivers/input/keyboard/atkbd.ko
~/w/linux-stable $ sudo update-initramfs -u
update-initramfs: Generating /boot/initrd.img-4.10.12
```
