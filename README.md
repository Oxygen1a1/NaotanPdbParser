# NaotanPdbParser
Very easy to use pdb parsing library with only one header file，You can use it even if you are a fool.
You can get function rva, structure offset, and get the name based on rva!
This library has only one header file and is used as follows
1. Select the Microsoft symbol analysis website or mirror website
```C++
namespace oxygenPdb {
	//Modify the download symbol website here, msdl is too slow, I use the mirror
#define DOWNLOAD_WEB "http://msdl.blackint3.com:88/download/symbols/"
```
3. Use the following code
```C++
  	oxygenPdb::NaotanPdber nt("ntoskrnl.exe");
	oxygenPdb::NaotanPdber k32("kernelbase.dll");
	oxygenPdb::NaotanPdber w32("win32k.sys");

	//ntoskrnl.exe
	auto nt_open_rva = nt.getRvaByName<ULONG>("NtOpenProcess");
	auto nt_open = nt.getNameByRva(nt_open_rva);
	auto offset = nt.getOffsetByStructAndMember("_KTHREAD", L"PreviousMode");
	auto nt_ssdt_rva=nt.getRvaByName<ULONG>("KeServiceDescriptorTable");
	
	//kernel32
	auto k32_write_rva = k32.getRvaByName<ULONG>("WriteProcessMemory");
	auto k32_write = k32.getNameByRva(k32_write_rva);

	//win32k.sys
	auto w32_eng_rva = w32.getRvaByName<ULONG>("EngCreatePath");
	auto w32_eng = w32.getNameByRva(w32_eng_rva);

	printf("[+]ntoskrnl.exe ->%s rva is 0x%x,previousMode offset is 0x%x,ssdt rva is 0x%x\r\n", nt_open.c_str(), nt_open_rva, offset, nt_ssdt_rva);
	printf("[+]kernelbase.dll -> %s rva is 0x%x\r\n", k32_write.c_str(), k32_write_rva);
	printf("[+]win32k.sys -> %s rva is 0x%x\r\n", w32_eng.c_str(), w32_eng_rva);
   ```
