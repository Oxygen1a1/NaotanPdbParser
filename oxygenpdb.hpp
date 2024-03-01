#pragma once
#include <windows.h>
#include <DbgHelp.h>
#include <string>
#include <iostream>
#include <cstring>
#include <urlmon.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"dbghelp.lib")

namespace oxygenPdb {
	//在这里修改下载符号网站,msdl太慢，我用的镜像
#define DOWNLOAD_WEB "http://msdl.blackint3.com:88/download/symbols/"


	/// <summary>
	/// 把下载和解析二者联合起来
	/// </summary>
	/// <typeparam name="Pdber_t"></typeparam>
	/// <typeparam name="PdbDownloader_t"></typeparam>
	template<typename Pdber_t,typename PdbDownloader_t>
	class PdbWrapper {
	public:
		PdbWrapper(const std::string& pdb_name);
		~PdbWrapper();
		PdbWrapper(const PdbWrapper& rhs);
		template<typename T>
		T getRvaByName(const std::string& name);
		template<typename T>
		std::string getNameByRva(T rva);
		unsigned getOffsetByStructAndMember(const std::string& struct_name, const std::wstring& mem_name);
		std::string getPdbName()const { return __pdb_name; }
	private:
		std::string __pdb_name;
		Pdber_t* __pdber;
		PdbDownloader_t __downloader;
	};


	template<typename Pdber_t, typename PdbDownloader_t>
	inline oxygenPdb::PdbWrapper<Pdber_t, PdbDownloader_t>::PdbWrapper(const PdbWrapper& rhs):__downloader(rhs.getPdbName())
	{
		__pdb_name = rhs.__pdb_name;
		
		__pdber = new Pdber_t(__downloader.getDownloadPdbPath());
	}

	template<typename Pdber_t, typename PdbDownloader_t>
	template<typename T>
	inline T oxygenPdb::PdbWrapper<Pdber_t, PdbDownloader_t>::getRvaByName(const std::string& name)
	{
		return __pdber->getRvaByName<T>(name);
	}

	template<typename Pdber_t, typename PdbDownloader_t>
	template<typename T>
	inline std::string oxygenPdb::PdbWrapper<Pdber_t, PdbDownloader_t>::getNameByRva(T rva)
	{
		return __pdber->getNameByRva<T>(rva);
	}

	template<typename Pdber_t, typename PdbDownloader_t>
	inline unsigned oxygenPdb::PdbWrapper<Pdber_t, PdbDownloader_t>::getOffsetByStructAndMember(const std::string& struct_name, const std::wstring& mem_name)
	{
		return __pdber->getOffsetByStructAndMember(struct_name, mem_name);
	}

	template<typename Pdber_t, typename PdbDownloader_t>
	inline oxygenPdb::PdbWrapper<Pdber_t, PdbDownloader_t>::PdbWrapper(const std::string& file_name):__downloader(file_name), __pdb_name(file_name)
	{

		__pdber = new Pdber_t(__downloader.getDownloadPdbPath());

	}

	template<typename Pdber_t, typename PdbDownloader_t>
	inline oxygenPdb::PdbWrapper<Pdber_t, PdbDownloader_t>::~PdbWrapper()
	{
		delete __pdber;
	}

	/// <summary>
	/// 抓门负责下载 不负责解析
	/// </summary>
	class PdbDownloader {
	public:
		PdbDownloader(const std::string& file_name);
		~PdbDownloader();
		std::string getDownloadPdbPath() const { return __download_path; }
	private:
		bool isFileExits(const std::string& file_path);
	private:
		std::string __file_name;
		std::string __download_path;
		std::string __file_md5;/*不必计算md5*/
		std::string __pdb_name;
		std::string __download_url;
	};


	inline bool oxygenPdb::PdbDownloader::isFileExits(const std::string& file_path)
	{
		auto fileAttr = GetFileAttributesA(file_path.c_str());
		return (fileAttr != INVALID_FILE_ATTRIBUTES &&
			!(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
	}

	struct PdbInfo
	{
		DWORD	Signature;
		GUID	Guid;
		DWORD	Age;
		char	PdbFileName[1];
	};

	inline PdbDownloader::PdbDownloader(const std::string& file_name) :__file_name(file_name)
	{
		char sys_path[MAX_PATH]{};
		GetSystemDirectoryA(sys_path, sizeof sys_path);
		auto full_path = std::string(sys_path) +"\\" + __file_name;
		auto image_base = (UINT_PTR)LoadLibraryExA(full_path.c_str(), 0, DONT_RESOLVE_DLL_REFERENCES);
		
		if (image_base != 0) {

			//通过PE结构获取pdb文件的相关信息
			const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
			const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + dos_header->e_lfanew);
			//get debug dir
			if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_headers->Signature != IMAGE_NT_SIGNATURE) {
				throw std::runtime_error("not vaild pe file");
			}
			const auto dbg_dir = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(image_base +
				nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
			const auto pdbInfo = reinterpret_cast<PdbInfo*>(image_base + dbg_dir->AddressOfRawData);

			__file_md5.resize(40);
			memset(&__file_md5[0], 0, 40);

			sprintf_s(&__file_md5[0],__file_md5.size(),
				"%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%x",
				pdbInfo->Guid.Data1, pdbInfo->Guid.Data2, pdbInfo->Guid.Data3,
				pdbInfo->Guid.Data4[0], pdbInfo->Guid.Data4[1], pdbInfo->Guid.Data4[2], pdbInfo->Guid.Data4[3],
				pdbInfo->Guid.Data4[4], pdbInfo->Guid.Data4[5], pdbInfo->Guid.Data4[6], pdbInfo->Guid.Data4[7],
				pdbInfo->Age);
			
			__pdb_name = pdbInfo->PdbFileName;

			__download_url = (DOWNLOAD_WEB + __pdb_name + "/" + __file_md5.c_str() + "/" + __pdb_name);

			//下载到当前目录 如果当前目录已经有了 那就不下载 直接返回
			char current_dir[MAX_PATH]{};
			GetCurrentDirectoryA(MAX_PATH, current_dir);
			__download_path = std::string(current_dir) +"\\" + __file_md5.c_str()+".pdb";

			if (!isFileExits(__download_path)) {
				CoInitialize(0);
				if (FAILED(URLDownloadToFileA(NULL, __download_url.c_str(), __download_path.c_str(), NULL, NULL))) {
					std::cout << "a" << std::endl;
					system("pause");
					throw std::runtime_error("failed to download pdb! please check network");
				}
				CoUninitialize();
			}
			//已经有了 不用再次下载
		}
		else {
			throw std::runtime_error("failed to load file in system directory!");
		}
		FreeLibrary((HMODULE)image_base);
	}

	inline oxygenPdb::PdbDownloader::~PdbDownloader()
	{

	}


	/// <summary>
	/// 负责解析pdb 不负责下载
	/// </summary>
	class Pdber {
	public:
		Pdber(const std::string& pdb_path);
		~Pdber();
		template<typename T>
		T getRvaByName(const std::string& name);
		template<typename T>
		std::string getNameByRva(T rva);
		unsigned getOffsetByStructAndMember(const std::string& struct_name, const std::wstring& mem_name);
	private:
		//std::string findSymbbolName(unsigned rva);
	private:
		std::string __pdb_path;
		const DWORD64 __mod_base= 0x10000000;
		HANDLE __handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		ULONG __pdb_size = 0;
	};


	inline oxygenPdb::Pdber::~Pdber()
	{
		CloseHandle(__handle);
		SymCleanup(__handle);
	}

	inline Pdber::Pdber(const std::string& pdb_path): __pdb_path(pdb_path)
	{

		auto ret=SymInitialize(__handle, __pdb_path.c_str(), FALSE);
	
		//get pdb size
		WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
		GetFileAttributesExA(__pdb_path.c_str(), GetFileExInfoStandard, &file_attr_data);
		auto pdb_size = file_attr_data.nFileSizeLow;

		if (!ret || __handle==INVALID_HANDLE_VALUE || pdb_size==0) {

			throw std::runtime_error(std::string("failed to load pdb!"));
		}

		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG | SYMOPT_LOAD_ANYTHING);
		auto SymbolTable = SymLoadModuleEx(__handle, NULL, __pdb_path.c_str(), NULL, __mod_base, pdb_size, NULL, NULL);
		if (SymbolTable == NULL) {
			throw std::runtime_error(std::string("failed to load pdb!"));
		}
	}

	template<typename T>
	inline T oxygenPdb::Pdber::getRvaByName(const std::string& name)
	{
		SYMBOL_INFO_PACKAGE symInfoPkg = { 0 };
		symInfoPkg.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		symInfoPkg.si.MaxNameLen = MAX_SYM_NAME;

		if (SymFromName(__handle, name.c_str(), &symInfoPkg.si)) {
			return static_cast<T>(symInfoPkg.si.Address - __mod_base);
		}
		auto error = GetLastError();
		return T{ 0 }; // 如果未找到，返回0或合适的错误代码
	}

	template<typename T>
	inline std::string oxygenPdb::Pdber::getNameByRva(T rva)
	{

		
		auto u_rva = (unsigned)(rva);
		DWORD64 address = __mod_base + u_rva;
		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
		PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol->MaxNameLen = MAX_SYM_NAME;

		if (SymFromAddr(__handle, address, NULL, symbol)) {
			return symbol->Name;
		}
		return "";
	}

	//copy from easy pdb,thank you,hambaga
	inline unsigned oxygenPdb::Pdber::getOffsetByStructAndMember(const std::string& struct_name, const std::wstring& mem_name)
	{
		auto info_size = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
		auto sys_info = reinterpret_cast<SYMBOL_INFO*>(malloc(info_size));
		sys_info->Size = info_size;
		sys_info->SizeOfStruct = sizeof(SYMBOL_INFO);
		sys_info->MaxNameLen = MAX_SYM_NAME;
		TI_FINDCHILDREN_PARAMS* child_params = nullptr;
		auto offset = 0xfffffffful;

		do {
			if (!SymGetTypeFromName(__handle, __mod_base, struct_name.c_str(), sys_info))
			{
				break;
			}

			TI_FINDCHILDREN_PARAMS temp_fp = { 0 };
			if (!SymGetTypeInfo(__handle, __mod_base, sys_info->TypeIndex, TI_GET_CHILDRENCOUNT, &temp_fp))
			{
				break;
			}

			ULONG child_size = sizeof(TI_FINDCHILDREN_PARAMS) + temp_fp.Count * sizeof(ULONG);
			child_params = (TI_FINDCHILDREN_PARAMS*)malloc(child_size);
			if (child_params == NULL)
			{
				break;
			}
			ZeroMemory(child_params, child_size);
			memcpy(child_params, &temp_fp, sizeof(TI_FINDCHILDREN_PARAMS));
			if (!SymGetTypeInfo(__handle, __mod_base, sys_info->TypeIndex, TI_FINDCHILDREN, child_params))
			{
				break;
			}
			for (ULONG i = child_params->Start; i < child_params->Count; i++)
			{
				WCHAR* pSymName = NULL;
				if (!SymGetTypeInfo(__handle, __mod_base, child_params->ChildId[i], TI_GET_OFFSET, &offset))
				{
					break;
				}
				if (!SymGetTypeInfo(__handle, __mod_base, child_params->ChildId[i], TI_GET_SYMNAME, &pSymName))
				{
					break;
				}
				if (pSymName)
				{
					//wprintf(L"%x %s\n", Offset, pSymName);
					if (wcscmp(pSymName, mem_name.c_str()) == 0)
					{
						LocalFree(pSymName);
						break;
					}
				}
			}
		} while (false);
		

		if (child_params != nullptr) {
			free(child_params);
		}
		if (sys_info != nullptr) {
			free(sys_info);
		}

		return  (ULONG)offset;
	}


	//脑瘫pdb解析
	using NaotanPdber = PdbWrapper<Pdber, PdbDownloader>;
}