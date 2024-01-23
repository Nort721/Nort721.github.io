---
title:  "Hardening the Windows kernel by monitoring driver loading"
date:   2024-01-13
tags: [posts]
excerpt: "This project hardens the Windows kernel by blocking drivers that appear in vulnerable or malicious driver databases"
---
Introduction
---
Privilege escalation exploits are nothing new, typically in the form of UAC bypasses, they have been used by attackers
to execute code with the capabilities to drastically change the user's computer and be able to access more sensitive
parts of the operating system.

However, Admin privileges are not the highest in the Windows operating system, the actual highest privilege is
NT Autority\System, this is the privilege level that all kernel-mode drivers run at and is limitless.

This is one of the reasons that any important program that requires performing system-wide tasks might load a kernel driver,
like Sysmon and any AV or EDR systems for example. But there is another advantage which is the kind of APIs
that are accessible to you, allowing you to register callbacks and notify routines that can be used to monitor events and execute code system-wide,
This for example allows monitoring of every process and thread creation, file read and writes you can monitor the creation
of processes handles and modify them which is often done to protect usermode processes from termination
or dumping. These are just some examples but the possibilities are near limitless.

Kernel defensive mechanism - DSE
---
Running code inside the Windows kernel is no doubt a powerful capability, which is why when Microsoft
first released Windows Vista it also introduced DSE.
Driver Signature Enforcement or DSE is a security feature that only allows drivers that have been
signed by Microsoft to be used, or more specifically when there is an attempt to load a driver
to the Windows kernel, DSE will check for a signature, if the driver isn't signed it will not load
the driver.

DSE is indeed a powerful security feature and for a long
time it has helped mitigate malicious kernel space code execution, however overtime researchers found
ways to bypass DSE and load unsigned drivers and today it has become very easy to do so. This
is a big security problem since as we explained before, an attacker having kernel code execution is pretty much
game over.

Vulnerable drivers compromising the kernel
---
Today, the most common way to bypass DSE is by loading an existing driver that has a write vulnerability
and from there using all sorts of tactics to mess up the DSE verification process by messing with the
memory in runtime.

This tactic is very common and has been known in cybersecurity communities for a while and there are working
code examples that can be easily found online.

Microsoft has tried to fight this by implementing a new mechanism into Windows that tries to detect
and block vulnerable drivers from being loaded but their databases of vulnerable drivers seem to not be updated quickly enough as its
still extremely easy to find signed vulnerable drivers online that aren't blocked. in addition to that lots of the vulnerable driver loader projects
are versatile and dynamic enough to the point where you can swap to another vulnerable driver with minimal
changes.

Another issue is that Microsoft is sometimes limited in which vulnerable drivers they can block since
sometimes that driver is going to be widely used and blocking it will break lots of computers, sometimes ones that perform extremely important tasks, in other
cases these machines simply won't be able to update due to a multitude of reasons.

Our hardening strategy with DLM
---
While Microsoft is working on mechanisms better than DSE to try and prevent malicious code execution and exploitation in kernel-space
these solutions are still early and can come with the cost of a lot of performance or create issues using other incompatible software.

In either case, we would like to make it harder for malware to perform kernel code execution, and we can do that by running code every time
software attempts to load a driver that checks if that driver is inside an external database of vulnerable or malicious drivers or even inside
our database that could contain drivers that are just easy to find online or that have been recently shared on hacking forums.

This gives us that much more control over which drivers are being loaded and in theory it can allow us to block drivers by all sorts
of parameters. Not only for appearing in a DB but based on certain methods appearing in its import table or certain byte patterns being
found in the binary, the possibilities are endless.

When inspecting driver loaders in most cases we find that they call NtLoadDriver from ntdll.dll, meaning if we hook
that function we will be able to execute our code and also decide whether we want to forward the call to the actual NtLoadDriver function.

Selecting the hooking strategy
---
I've decided to use an inline hook over an IAT hook because unlike IAT hooking where we just modify a data structure, inline hooking
involves modifying the code at the instruction level rather than altering data structures like the IAT. This can make it more challenging for anti-hooking techniques to identify and remove the hook.

Also, inline hooking provides better stability and compatibility since in some cases optimized or obfuscated code may not work well with IAT hooks due to the reliance on fixed addresses in the import table. Inline hooking, being more flexible and operating directly at the instruction level, can be more compatible with such scenarios.

Hooking NtLoadDriver
---
NtLoadDriver like most native API functions is undocumented but there is plenty of information about it online in lots of unofficial documentation websites and forums like undocumented.ntinternals.net, geoffchappell.com, and unknowncheats.me
just to name a few.

This is the function definition together with definitions of NTSTATUS STATUS_ACCESS_DENIED which we will return when the driver is found to be vulnerable or malicious and a max path size value which we will use later on.

![definitions](https://github.com/Nort721/Nort721.github.io/assets/24839815/dd4e0fb3-7722-4bfa-a4f7-4674afef16ff)

Next, declare the following two fields to store the original first 5 bytes of the function which we are going to replace with the trampoline and the address of NtLoadLibrary.

![declarations](https://github.com/Nort721/Nort721.github.io/assets/24839815/e19a6a0a-cf24-453b-a4b0-5f8a19de211c)
