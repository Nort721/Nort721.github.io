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

Selecting a hooking strategy
---
I've decided to use an inline hook over an IAT hook because, unlike IAT hooking, inline hooking
involves modifying the code at the instruction level rather than altering data structures. This can make it more challenging for anti-hooking techniques to identify and remove the hook.

Also, inline hooking provides better stability and compatibility since in some cases optimized or obfuscated code may not work well with IAT hooks due to the reliance on fixed addresses in the import table. Inline hooking, being more flexible and operating directly at the instruction level, can be more compatible with such scenarios.

Hooking NtLoadDriver
---
NtLoadDriver like most native API functions is undocumented but there is plenty of information about it online in lots of unofficial documentation websites and forums like undocumented.ntinternals.net, geoffchappell.com, and unknowncheats.me
just to name a few.

This is the function definition of NtLoadDrvier together with definitions of NTSTATUS STATUS_ACCESS_DENIED which we will return when the driver is found to be vulnerable or malicious and a max path size value which we will use later on.

![definitions](https://github.com/Nort721/Nort721.github.io/assets/24839815/dd4e0fb3-7722-4bfa-a4f7-4674afef16ff)


Next, we declare the following two fields to store the original first 5 bytes of the function which we are going to replace with the trampoline bytes and declare the address of NtLoadLibrary.

![declarations](https://github.com/Nort721/Nort721.github.io/assets/24839815/e19a6a0a-cf24-453b-a4b0-5f8a19de211c)


The hook is going to be inside a DLL that will be loaded to every process we want to monitor which in our case its all processes, the hook will be first installed when the DLL is attached to
a process.

![ScDllMainFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/3405377f-6ae5-4830-804b-dce4eafbc4e4)


The InstallInitHook function like its called installs the hook for the first time and initializes the rest of the hooking logic.

![ScInstallInitHookFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/d0fdf40a-f798-4215-bdfe-bc274caa4668)


InstallInlineHook is the function responsible for actually writing the hook or rather the trampoline to the first five bytes of the function, built out of 6 stages.
saving the original first five bytes, generating the trampoline bytes, changing memory permissions to allow for writing the hook bytes, writing the trampoline, changing memory permissions back to what they were,
clearing the instruction cash.

In a technical sense you don't have to set the memory permissions to what were but generally leaving messed up permissions behind is messy and if you are an attacker this leaves behind evidence, this doesn't
need to bother us in that sense because we are defending but this does hurt our stealthiness and can help indicate that this area contains a hook, so in either case, its good practice to stay clean.

As you can see, we are writing from the address of the function forward at the size of the trampoline.

![ScInstallInlineHookFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/c1cc0890-9cee-4aef-b1b8-35a6a9e78ed2)

![ScChangeMemPermFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/45a88b3d-3057-40a0-96a8-8ab0e32db7aa)


SaveBytes saves the bytes that are going to be overwritten by the bytes of the hook.

![ScSaveBytesFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/a3a00140-8b34-49f7-bff2-67e7db7c0f1d)


CreateInlineHookBytes creates an array containing the stub and copies the actual address to replace it with the placeholder 0xCC.

![ScCreateInlineHookBytesFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/dda769cc-4268-4594-93fb-86ff90588493)


HookNtLoadDriver is the function that we are jumping to every time NtLoadDriver is called, the parameter passed to NtLoadDriver is a pointer to a unicode string that contains
the registry pathname of the service of the driver, our hooked function operates in a few stages, first get the file system path for the binary of the driver, use the file to verify that the driver
is safe, if it is, remove the trampoline bytes so we can call NtLoadDriver and then write the trampoline bytes back so we don't miss future calls. 
if the driver is found to be not safe we simply return NTSTATUS - STATUS_ACCESS_DENIED.

![ScHookNtLoadDriverFunc](https://github.com/Nort721/Nort721.github.io/assets/24839815/eed140a3-7941-438b-afcd-050f25f74bed)


todo - explain VerifyDriverBinary . . .
