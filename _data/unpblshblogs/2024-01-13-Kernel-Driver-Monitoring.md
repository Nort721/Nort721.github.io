---
title:  "Monitoring driver loading to block vulnerable and malicious drivers"
date:   2024-01-13
tags: [posts]
excerpt: "This project hardens Windows kernel driver loading by listening to driver load attempts and comparing the driver hash to a db of vulnerable drivers"
---
Introduction
---
Privilege escalation exploits are nothing new, typically in the form of UAC bypasses, they have been used by hackers
to execute code with the capabilities to drastically change the user's computer and be able to access more sensitive
parts of the operating system.

However, Admin privileges are not the highest in the Windows operating system, the actual highest privilege is
nt autority, this is the privilege level that all kernel-mode drivers run at and is limitless.

This is one of the reasons that any system-wide important program might load a kernel driver,
and any AV and EDR systems as well. But there is another advantage which is the kind of APIs
that are accessible to you, allowing you to monitor and therefore perform actions system-wide,
This for example allows monitoring of every process and thread creation, file read, and writes, you can monitor the creation
of processes handles and modify them which is often done to protect usermode processes from termination
or dumping.

Microsoft's first attempts
---
Running code inside the Windows kernel is no doubt a powerful capability, which is why when Microsoft
first released Windows Vista it also introduced DSE.
Driver Signature Enforcement or DSE is a security feature that only allows drivers that have been
signed by Microsoft to be used, or more specifically when there is an attempt to load a driver
to the Windows kernel, DSE will check for a signature, if the driver isn't signed it will not load
the driver.

DSE was indeed a powerful new security feature that have been implemented to Windows, and for a long
time it has helped mitigate malicious kernel space code execution, however overtime researchers found
ways to bypass DSE and load unsigned drivers and today it has become very easy to do so and this
is a big security problem since as we explained before, an attacker having kernel code execution is
game over.

DSE bypass
---
Today, the most common way to bypass DSE is by loading an existing driver that has a write vulnerability
and from there using all sorts of tactics to mess up the DSE verification process by messing with the
memory in runtime.

This tactic is very common and has been known in cybersecurity communities for a while and there are working
code examples that can be easily found online.

Microsoft has tried to fight this by implementing a new mechanism into Windows that tries to detect
and block vulnerable drivers from being loaded but their databases of vulnerable drivers seem to not be updated quickly enough as its
still extremely easy to find signed vulnerable drivers online that aren't blocked and lots of the vulnerable driver loader projects
are versatile and dynamic enough to the point where you can swap to another vulnerable driver with minimal
changes.

Another issue is that Microsoft is sometimes limited in which vulnerable drivers they can block and when since
sometimes that driver is going to be widely used and blocking it will break lots of running machines, in other
cases these machines simply won't be able to update due to a multitude of reasons.

Our hardening strategy with DLM
---
While Microsoft is working on much smarter mechanisms from DSE to try and prevent malicious code execution and exploitation in kernel-space
these solutions are still early, and can come with the cost of a lot of performance or create issues using other incompatible software.

In either case we would like to make it harder for malware perform kernel code execution, and we can do that by running code every time
software attempts to load a driver that checks if that driver is inside an external database of vulnerable or malicious drivers or even inside
our own database that could contain drivers that are just easy to find online or that have been recently shared on hacking forums.

This gives us that much more control over which drivers are being loaded and in theory it can allow us to block drivers by all sorts
of parameters. Not only for appearing in a DB but based on certain methods appearing in its import table or certain byte patterns being
found in the binary, the possibilities are endless.

In inspecting malwares and most other software that loads drivers we find that they call NtLoadDriver from ntdll.dll, meaning if we hook
that function we will be able to execute our own code and also decide whether we want to forward the call to the actual NtLoadDriver function.

Placing an inline hook on NtLoadDriver
---
I've decided to go with an inline hook because . . .
