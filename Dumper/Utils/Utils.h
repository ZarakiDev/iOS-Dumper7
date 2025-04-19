#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

/* Credits: https://en.cppreference.com/w/cpp/string/byte/tolower */
inline std::string str_tolower(std::string S)
{
	std::transform(S.begin(), S.end(), S.begin(), [](unsigned char C) { return std::tolower(C); });
	return S;
}

template<typename CharType>
inline int32_t StrlenHelper(const CharType* Str)
{
	if constexpr (std::is_same<CharType, char>())
	{
		return strlen(Str);
	}
    else if constexpr (std::is_same<CharType, char16_t>())
    {
        return std::char_traits<char16_t>::length(Str);
    }
	else
	{
		return wcslen(Str);
	}
}

template<typename CharType>
inline bool StrnCmpHelper(const CharType* Left, const CharType* Right, size_t NumCharsToCompare)
{
	if constexpr (std::is_same<CharType, char>())
	{
		return strncmp(Left, Right, NumCharsToCompare) == 0;
	}
    else if constexpr (std::is_same<CharType, char16_t>())
    {
        return std::char_traits<char16_t>::compare(Left, Right, NumCharsToCompare) == 1;
    }
	else
	{
		return wcsncmp(Left, Right, NumCharsToCompare) == 0;
	}
}

namespace ASMUtils
{
    // Check if the instruction is a B/BL/B.cond (i.e., relative branch)
    inline bool IsBranchInstruction(uint32_t instruction)
    {
        // Check top 6 bits for 0b000101 (B) or 0b100101 (BL)
        return (instruction & 0xFC000000) == 0x14000000 || (instruction & 0xFC000000) == 0x94000000;
    }

    // Resolves a 26-bit immediate branch (B/BL) to its absolute address
    inline uintptr_t ResolveBranchTarget(uintptr_t Address)
    {
        uint32_t instr = *reinterpret_cast<uint32_t*>(Address);

        // Instruction format: B/BL <label>
        // Offset is bits[25:0] << 2 (sign-extended)
        int32_t imm26 = (instr & 0x03FFFFFF);
        int64_t offset = (int64_t)(imm26 << 6) >> 4; // sign extend to 64 bits

        return Address + offset;
    }

    // Check for ADRP (used for PC-relative loads to registers)
    inline bool IsADRP(uint32_t instruction)
    {
        return (instruction & 0x9F000000) == 0x90000000;
    }

    // Resolves target of an ADRP instruction
    inline uintptr_t ResolveADRP(uintptr_t Address)
    {
        uint32_t instr = *reinterpret_cast<uint32_t*>(Address);
        uint64_t pc_page = Address & ~0xFFFULL;

        // Extract immhi and immlo
        uint64_t immhi = (instr >> 5) & 0x7FFFF;
        uint64_t immlo = (instr >> 29) & 0x3;

        // Sign-extend 21-bit immediate
        int64_t imm = ((int64_t)((immhi << 2) | immlo) << 43) >> 31;

        return pc_page + imm;
    }

    // Check for LDR literal (PC-relative loads)
    inline bool IsLDRLiteral(uint32_t instruction)
    {
        // LDR (literal) has opcode 0b0001xx (depending on size)
        return (instruction & 0x3B000000) == 0x18000000;
    }

    // Resolves the target of a PC-relative LDR instruction
    inline uintptr_t ResolveLDRLiteral(uintptr_t Address)
    {
        uint32_t instr = *reinterpret_cast<uint32_t*>(Address);

        // 19-bit signed offset, shifted by scale (size)
        int32_t imm19 = (instr >> 5) & 0x7FFFF;
        int32_t offset = (imm19 << 13) >> 11; // sign-extend

        return Address + offset;
    }

    inline bool IsADRL(uint32_t* address)
    {
        uint32_t adrp = address[0];
        uint32_t add  = address[1];

        bool isAdrp = (adrp & 0x9F000000) == 0x90000000; // ADRP opcode
        bool isAdd  = (add  & 0xFFC00000) == 0x91000000; // ADD (immediate)

        uint32_t adrpReg = adrp & 0x1F;          // destination register of ADRP
        uint32_t addBase = (add >> 5) & 0x1F;    // base register of ADD
        uint32_t addDest = add & 0x1F;           // destination register of ADD

        return isAdrp && isAdd && (adrpReg == addBase) && (addDest == adrpReg);
    }

    inline uintptr_t ResolveADRL(uintptr_t address)
    {
        uint32_t* instrs = reinterpret_cast<uint32_t*>(address);

        uint32_t adrp = instrs[0];
        uint32_t add  = instrs[1];

        // Resolve ADRP
        uint64_t pc_page = address & ~0xFFFULL;
        uint64_t immhi = (adrp >> 5) & 0x7FFFF;
        uint64_t immlo = (adrp >> 29) & 0x3;
        int64_t adrpImm = ((int64_t)((immhi << 2) | immlo) << 43) >> 31;

        uintptr_t adrpResult = pc_page + adrpImm;

        // Resolve ADD immediate
        uint32_t imm12 = (add >> 10) & 0xFFF;
        uint32_t shift = (add >> 22) & 0x1; // If set, shift imm12 by 12

        uintptr_t addResult = adrpResult + (imm12 << (shift ? 12 : 0));

        return addResult;
    }

    inline bool IsSTR(uint32_t instruction)
    {
        return (instruction & 0x3B000000) == 0x39000000;
    }

    inline uintptr_t ResolveSTR(uintptr_t address)
    {
        uint32_t instr = *reinterpret_cast<uint32_t*>(address);

        uint32_t baseReg = (instr >> 5) & 0x1F;
        uint32_t imm12   = (instr >> 10) & 0xFFF;
        uint32_t size    = (instr >> 30) & 0x3; // 00=8bit, 01=16bit, 10=32bit, 11=64bit
        uint32_t scale   = size; // scale is log2 of size in bytes

        // You need the actual value of the base register at runtime to resolve this!
        // For now, we can only say: offset = base + (imm12 << scale)
        uintptr_t offset = (imm12 << scale);
        return /* base value */ + offset;
    }


}


inline uintptr_t GetModuleBase(const char* const ModuleName = nullptr)
{
	if (ModuleName == nullptr)
		return (uintptr_t)_dyld_get_image_header(0);

    for (uint32_t Idx = 0; Idx < _dyld_image_count(); ++Idx)
    {
        const char* dyld_name = _dyld_get_image_name(Idx);
        if (strstr(dyld_name, ModuleName))
        {
            return (uintptr_t)_dyld_get_image_header(Idx);
        }
    }
    return 0;
}


inline std::pair<uintptr_t, uintptr_t> GetImageBaseAndSize(const char* const ModuleName = nullptr)
{
    for (uint32_t i = 0; i < _dyld_image_count(); ++i)
    {
        const char* name = _dyld_get_image_name(i);
        if (!ModuleName || strstr(name, ModuleName))
        {
            const mach_header* header = _dyld_get_image_header(i);
            uintptr_t base = reinterpret_cast<uintptr_t>(header) + _dyld_get_image_vmaddr_slide(i);
            
            const load_command* cmd = reinterpret_cast<const load_command*>(header + 1);
            uintptr_t max_addr = base;

            for (uint32_t j = 0; j < header->ncmds; ++j)
            {
                if (cmd->cmd == LC_SEGMENT_64)
                {
                    auto seg = reinterpret_cast<const segment_command_64*>(cmd);
                    uintptr_t end = base + seg->vmaddr + seg->vmsize;
                    if (end > max_addr)
                        max_addr = end;
                }
                cmd = reinterpret_cast<const load_command*>((uintptr_t)cmd + cmd->cmdsize);
            }
            return { base, max_addr - base };
        }
    }
    return { 0, 0 };
}


std::pair<uintptr_t, size_t> GetSectionByName(const char* SegmentName, const char* SectionName, const char* ModuleName = nullptr)
{
    for (uint32_t i = 0; i < _dyld_image_count(); ++i)
    {
        const char* name = _dyld_get_image_name(i);
        if (!ModuleName || strstr(name, ModuleName))
        {
            const mach_header_64* header = (const mach_header_64*)_dyld_get_image_header(i);
            uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
            const load_command* cmd = (const load_command*)(header + 1);

            for (uint32_t j = 0; j < header->ncmds; ++j)
            {
                if (cmd->cmd == LC_SEGMENT_64)
                {
                    const segment_command_64* seg = (const segment_command_64*)cmd;
                    if (strcmp(seg->segname, SegmentName) == 0)
                    {
                        const section_64* sec = (const section_64*)((uintptr_t)seg + sizeof(segment_command_64));
                        for (uint32_t k = 0; k < seg->nsects; ++k)
                        {
                            if (strcmp(sec->sectname, SectionName) == 0)
                                return { slide + sec->addr, sec->size };
                            sec++;
                        }
                    }
                }
                cmd = (const load_command*)((uintptr_t)cmd + cmd->cmdsize);
            }
        }
    }
    return { 0, 0 };
}

inline uintptr_t GetOffset(const uintptr_t Address)
{
	static uintptr_t ImageBase = 0x0;

	if (ImageBase == 0x0)
		ImageBase = GetModuleBase();

	return Address > ImageBase ? (Address - ImageBase) : 0x0;
}

inline uintptr_t GetOffset(const void* Address)
{
	return GetOffset(reinterpret_cast<const uintptr_t>(Address));
}

inline bool IsInAnyModules(const uintptr_t Address)
{
    for (uint32_t i = 0; i < _dyld_image_count(); ++i)
    {
        const mach_header* header = _dyld_get_image_header(i);
        uintptr_t base = reinterpret_cast<uintptr_t>(header) + _dyld_get_image_vmaddr_slide(i);

        const load_command* cmd = reinterpret_cast<const load_command*>(header + 1);
        uintptr_t maxAddr = base;

        for (uint32_t j = 0; j < header->ncmds; ++j)
        {
            if (cmd->cmd == LC_SEGMENT_64)
            {
                auto seg = reinterpret_cast<const segment_command_64*>(cmd);
                uintptr_t end = base + seg->vmaddr + seg->vmsize;
                if (Address >= (base + seg->vmaddr) && Address < end)
                    return true;

                if (end > maxAddr)
                    maxAddr = end;
            }
            cmd = reinterpret_cast<const load_command*>((uintptr_t)cmd + cmd->cmdsize);
        }
    }
    return false;
}

inline bool IsBadReadPtr(const void* Ptr)
{
    uint8_t Data = 0;
    size_t Size = 0;
    
    kern_return_t KR = vm_read_overwrite(mach_task_self(), (vm_address_t)Ptr, 1, (vm_address_t)&Data, &Size);
    return (KR == KERN_INVALID_ADDRESS ||
            KR == KERN_MEMORY_FAILURE  ||
            KR == KERN_MEMORY_ERROR    ||
            KR == KERN_PROTECTION_FAILURE);
};

inline bool IsBadReadPtr(const uintptr_t Ptr)
{
    return IsBadReadPtr(reinterpret_cast<const void*>(Ptr));
}

inline bool IsValidVirtualAddress(const uintptr_t Address)
{
    return !IsBadReadPtr(Address);
}

inline bool IsInProcessRange(const uintptr_t Address)
{
    const auto [Base, Size] = GetImageBaseAndSize();
    if (Address >= Base && Address < (Base + Size))
        return true;

    return IsInAnyModules(Address);
}

inline bool IsInProcessRange(const void* Address)
{
    return IsInProcessRange(reinterpret_cast<const uintptr_t>(Address));
}


inline void* GetModuleAddress(const char* SearchModuleName)
{
	LDR_DATA_TABLE_ENTRY* Entry = GetModuleLdrTableEntry(SearchModuleName);

	if (Entry)
		return Entry->DllBase;

	return nullptr;
}

/* Gets the address at which a pointer to an imported function is stored */
inline PIMAGE_THUNK_DATA GetImportAddress(uintptr_t ModuleBase, const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	/* Get the module importing the function */
	PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);

	if (ModuleBase == 0x0 || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase)->e_lfanew);

	if (!NtHeader)
		return nullptr;

	PIMAGE_IMPORT_DESCRIPTOR ImportTable = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ModuleBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//std::cout << "ModuleName: " << (SearchModuleName ? SearchModuleName : "Default") << std::endl;

	/* Loop all modules and if we found the right one, loop all imports to get the one we need */
	for (PIMAGE_IMPORT_DESCRIPTOR Import = ImportTable; Import && Import->Characteristics != 0x0; Import++)
	{
		if (Import->Name == 0xFFFF)
			continue;

		const char* Name = reinterpret_cast<const char*>(ModuleBase + Import->Name);

		//std::cout << "Name: " << str_tolower(Name) << std::endl;

		if (str_tolower(Name) != str_tolower(ModuleToImportFrom))
			continue;

		PIMAGE_THUNK_DATA NameThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(ModuleBase + Import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FuncThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(ModuleBase + Import->FirstThunk);

		while (!IsBadReadPtr(NameThunk)
			&& !IsBadReadPtr(FuncThunk)
			&& !IsBadReadPtr(ModuleBase + NameThunk->u1.AddressOfData)
			&& !IsBadReadPtr(FuncThunk->u1.AddressOfData))
		{
			/*
			* A functin might be imported using the Ordinal (Index) of this function in the modules export-table
			*
			* The name could probably be retrieved by looking up this Ordinal in the Modules export-name-table
			*/
			if ((NameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0) // No ordinal
			{
				NameThunk++;
				FuncThunk++;
				continue; // Maybe Handle this in the future
			}

			/* Get Import data for this function */
			PIMAGE_IMPORT_BY_NAME NameData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ModuleBase + NameThunk->u1.ForwarderString);
			PIMAGE_IMPORT_BY_NAME FunctionData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(FuncThunk->u1.AddressOfData);

			//std::cout << "IMPORT: " << std::string(NameData->Name) << std::endl;

			if (std::string(NameData->Name) == SearchFunctionName)
				return FuncThunk;

			NameThunk++;
			FuncThunk++;
		}
	}

	return nullptr;
}

/* Gets the address at which a pointer to an imported function is stored */
inline PIMAGE_THUNK_DATA GetImportAddress(const char* SearchModuleName, const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	const uintptr_t SearchModule = SearchModuleName ? reinterpret_cast<uintptr_t>(GetModuleAddress(SearchModuleName)) : GetModuleBase();

	return GetImportAddress(SearchModule, ModuleToImportFrom, SearchFunctionName);
}

/* Finds the import for a funciton and returns the address of the function from the imported module */
inline void* GetAddressOfImportedFunction(const char* SearchModuleName, const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	PIMAGE_THUNK_DATA FuncThunk = GetImportAddress(SearchModuleName, ModuleToImportFrom, SearchFunctionName);

	if (!FuncThunk)
		return nullptr;

	return reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(FuncThunk->u1.AddressOfData);
}

inline void* GetAddressOfImportedFunctionFromAnyModule(const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	PEB* Peb = GetPEB();
	PEB_LDR_DATA* Ldr = Peb->Ldr;

	int NumEntriesLeft = Ldr->Length;

	for (LIST_ENTRY* P = Ldr->InMemoryOrderModuleList.Flink; P && NumEntriesLeft-- > 0; P = P->Flink)
	{
		LDR_DATA_TABLE_ENTRY* Entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(P);

		PIMAGE_THUNK_DATA Import = GetImportAddress(reinterpret_cast<uintptr_t>(Entry->DllBase), ModuleToImportFrom, SearchFunctionName);

		if (Import)
			return reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(Import->u1.AddressOfData);
	}

	return nullptr;
}

/* Gets the address of an exported function */
inline void* GetExportAddress(const char* SearchModuleName, const char* SearchFunctionName)
{
	/* Get the module the function was exported from */
	uintptr_t ModuleBase = reinterpret_cast<uintptr_t>(GetModuleAddress(SearchModuleName));
	PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);

	if (ModuleBase == 0x0 || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase)->e_lfanew);

	if (!NtHeader)
		return nullptr;

	/* Get the table of functions exported by the module */
	PIMAGE_EXPORT_DIRECTORY ExportTable = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ModuleBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	const DWORD* NameOffsets = reinterpret_cast<const DWORD*>(ModuleBase + ExportTable->AddressOfNames);
	const DWORD* FunctionOffsets = reinterpret_cast<const DWORD*>(ModuleBase + ExportTable->AddressOfFunctions);

	const WORD* Ordinals = reinterpret_cast<const WORD*>(ModuleBase + ExportTable->AddressOfNameOrdinals);

	/* Iterate all names and return the function if the name matches what we're looking for */
	for (int i = 0; i < ExportTable->NumberOfFunctions; i++)
	{
		const WORD NameIndex = Ordinals[i];
		const char* Name = reinterpret_cast<const char*>(ModuleBase + NameOffsets[NameIndex]);

		if (strcmp(SearchFunctionName, Name) == 0)
			return reinterpret_cast<void*>(ModuleBase + FunctionOffsets[i]);
	}

	return nullptr;
}

inline void* FindPatternInRange(std::vector<int>&& Signature, const uint8_t* Start, uintptr_t Range, bool bRelative = false, uint32_t Offset = 0, int SkipCount = 0)
{
	const auto PatternLength = Signature.size();
	const auto PatternBytes = Signature.data();

	for (int i = 0; i < (Range - PatternLength); i++)
	{
		bool bFound = true;
		int CurrentSkips = 0;

		for (auto j = 0ul; j < PatternLength; ++j)
		{
			if (Start[i + j] != PatternBytes[j] && PatternBytes[j] != -1)
			{
				bFound = false;
				break;
			}
		}
		if (bFound)
		{
			if (CurrentSkips != SkipCount)
			{
				CurrentSkips++;
				continue;
			}

			uintptr_t Address = uintptr_t(Start + i);
			if (bRelative)
			{
				if (Offset == -1)
					Offset = PatternLength;

				Address = ((Address + Offset + 4) + *reinterpret_cast<int32_t*>(Address + Offset));
			}
			return reinterpret_cast<void*>(Address);
		}
	}

	return nullptr;
}

inline void* FindPatternInRange(const char* Signature, const uint8_t* Start, uintptr_t Range, bool bRelative = false, uint32_t Offset = 0)
{
	static auto patternToByte = [](const char* pattern) -> std::vector<int>
	{
		auto Bytes = std::vector<int>{};
		const auto Start = const_cast<char*>(pattern);
		const auto End = const_cast<char*>(pattern) + strlen(pattern);

		for (auto Current = Start; Current < End; ++Current)
		{
			if (*Current == '?')
			{
				++Current;
				if (*Current == '?') ++Current;
				Bytes.push_back(-1);
			}
			else { Bytes.push_back(strtoul(Current, &Current, 16)); }
		}
		return Bytes;
	};

	return FindPatternInRange(patternToByte(Signature), Start, Range, bRelative, Offset);
}

inline void* FindPattern(const char* Signature, uint32_t Offset = 0, bool bSearchAllSections = false, uintptr_t StartAddress = 0x0)
{
	//std::cout << "StartAddr: " << StartAddress << "\n";

	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uintptr_t SearchStart = ImageBase;
	uintptr_t SearchRange = ImageSize;

	if (!bSearchAllSections)
	{
		const auto [TextSection, TextSize] = GetSectionByName(ImageBase, ".text");

		if (TextSection != 0x0 && TextSize != 0x0)
		{
			SearchStart = TextSection;
			SearchRange = TextSize;
		}
		else
		{
			bSearchAllSections = true;
		}
	}

	const uintptr_t SearchEnd = ImageBase + SearchRange;

	/* If the StartAddress is not default nullptr, and is out of memory-range */
	if (StartAddress != 0x0 && (StartAddress < SearchStart || StartAddress >= SearchEnd))
		return nullptr;

	/* Add a byte to the StartAddress to prevent instantly returning the previous result */
	SearchStart = StartAddress != 0x0 ? (StartAddress + 0x1) : ImageBase;
	SearchRange = StartAddress != 0x0 ? SearchEnd - StartAddress : ImageSize;

	return FindPatternInRange(Signature, reinterpret_cast<uint8_t*>(SearchStart), SearchRange, Offset != 0x0, Offset);
}


template<typename T>
inline T* FindAlignedValueInProcessInRange(T Value, int32_t Alignment, uintptr_t StartAddress, uint32_t Range)
{
	constexpr int32_t ElementSize = sizeof(T);

	for (uint32_t i = 0x0; i < Range; i += Alignment)
	{
		T* TypedPtr = reinterpret_cast<T*>(StartAddress + i);

		if (*TypedPtr == Value)
			return TypedPtr;
	}

	return nullptr;
}

template<typename T>
inline T* FindAlignedValueInProcess(T Value, const std::string& Sectionname = ".data", int32_t Alignment = alignof(T), bool bSearchAllSections = false)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uintptr_t SearchStart = ImageBase;
	uintptr_t SearchRange = ImageSize;

	if (!bSearchAllSections)
	{
		const auto [SectionStart, SectionSize] = GetSectionByName(ImageBase, Sectionname);

		if (SectionStart != 0x0 && SectionSize != 0x0)
		{
			SearchStart = SectionStart;
			SearchRange = SectionSize;
		}
		else
		{
			bSearchAllSections = true;
		}
	}

	T* Result = FindAlignedValueInProcessInRange(Value, Alignment, SearchStart, SearchRange);

	if (!Result && SearchStart != ImageBase)
		return FindAlignedValueInProcess(Value, Sectionname, Alignment, true);

	return Result;
}

template<bool bShouldResolve32BitJumps = true>
inline std::pair<const void*, int32_t> IterateVTableFunctions(void** VTable, const std::function<bool(const uint8_t* Addr, int32_t Index)>& CallBackForEachFunc, int32_t NumFunctions = 0x150, int32_t OffsetFromStart = 0x0)
{
	[[maybe_unused]] auto Resolve32BitRelativeJump = [](const void* FunctionPtr) -> const uint8_t*
	{
		if constexpr (bShouldResolve32BitJumps)
		{
			const uint8_t* Address = reinterpret_cast<const uint8_t*>(FunctionPtr);
			if (*Address == 0xE9)
			{
				const uint8_t* Ret = ((Address + 5) + *reinterpret_cast<const int32_t*>(Address + 1));

				if (IsInProcessRange(Ret))
					return Ret;
			}
		}

		return reinterpret_cast<const uint8_t*>(FunctionPtr);
	};


	if (!CallBackForEachFunc)
		return { nullptr, -1 };

	for (int i = 0; i < 0x150; i++)
	{
		const uintptr_t CurrentFuncAddress = reinterpret_cast<uintptr_t>(VTable[i]);

		if (CurrentFuncAddress == NULL || !IsInProcessRange(CurrentFuncAddress))
			break;

		const uint8_t* ResolvedAddress = Resolve32BitRelativeJump(reinterpret_cast<const uint8_t*>(CurrentFuncAddress));

		if (CallBackForEachFunc(ResolvedAddress, i))
			return { ResolvedAddress, i };
	}

	return { nullptr, -1 };
}

struct MemAddress
{
public:
	uintptr_t Address;

private:
	//pasted
	static std::vector<int32_t> PatternToBytes(const char* pattern)
	{
		auto bytes = std::vector<int>{};
		const auto start = const_cast<char*>(pattern);
		const auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else { bytes.push_back(strtoul(current, &current, 16)); }
		}
		return bytes;
	}

	/* Function to determine whether this position is a function-return. Only "ret" instructions with pop operations before them and without immediate values are considered. */
	static bool IsFunctionRet(const uint8_t* Address)
	{
		if (!Address || (Address[0] != 0xC3 && Address[0] != 0xCB))
			return false;

		/* Opcodes representing pop instructions for x64 registers. Pop operations for r8-r15 are prefixed with 0x41. */
		const uint8_t AsmBytePopOpcodes[] = { 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F };

		const uint8_t ByteOneBeforeRet = Address[-1];
		const uint8_t ByteTwoBeforeRet = Address[-2];

		for (const uint8_t AsmPopByte : AsmBytePopOpcodes)
		{
			if (ByteOneBeforeRet == AsmPopByte)
				return true;
		}

		return false;
	}

public:
	inline MemAddress(std::nullptr_t)
		: Address(NULL)
	{
	}
	inline MemAddress(void* Addr)
		: Address(reinterpret_cast<uintptr_t>(Addr))
	{
	}
	inline MemAddress(uintptr_t Addr)
		: Address(Addr)
	{
	}

	explicit operator bool()
	{
		return Address != NULL;
	}

	template<typename T>
	explicit operator T*()
	{
		return reinterpret_cast<T*>(Address);
	}
	operator uintptr_t()
	{
		return Address;
	}

	inline bool operator==(MemAddress Other) const
	{
		return Address == Other.Address;
	}

	inline MemAddress operator+(int Value) const
	{
		return Address + Value;
	}

	inline MemAddress operator-(int Value) const
	{
		return Address - Value;
	}

	template<typename T = void>
	inline T* Get()
	{
		return reinterpret_cast<T*>(Address);
	}

	template<typename T = void>
	inline const T* Get() const
	{
		return reinterpret_cast<const T*>(Address);
	}

	/* 
	* Checks if the current address is a valid 32-bit relative 'jmp' instruction. and returns the address if true. 
	* 
	* If true: Returns resolved jump-target.
	* If false: Returns current address.
	*/
	inline MemAddress ResolveJumpIfInstructionIsJump(MemAddress DefaultReturnValueOnFail = nullptr) const
	{
		if (!ASMUtils::Is32BitRIPRelativeJump(Address))
			return DefaultReturnValueOnFail;

		const uintptr_t TargetAddress = ASMUtils::Resolve32BitRIPRelativeJumpTarget(Address);

		if (!IsInProcessRange(TargetAddress))
			return DefaultReturnValueOnFail;

		return TargetAddress;
	}

	/* Helper to find the end of a function based on 'pop' instructions followed by 'ret' */
	inline MemAddress FindFunctionEnd(uint32_t Range = 0xFFFF) const
	{
		if (!Address)
			return nullptr;

		if (Range > 0xFFFF)
			Range = 0xFFFF;

		for (int i = 0; i < Range; i++)
		{
			if (IsFunctionRet(Get<uint8_t>() + i))
				return Address + i;
		}

		return  nullptr;
	}

	/* Helper function to find a Pattern in a Range relative to the current position */
	inline MemAddress RelativePattern(const char* Pattern, int32_t Range, int32_t Relative = 0) const
	{
		if (!Address)
			return nullptr;

		return FindPatternInRange(Pattern, Get<uint8_t>(), Range, Relative != 0, Relative);
	}

	/*
	* A Function to find calls relative to the instruction pointer (RIP). Other calls are ignored.
	* 
	* Disclaimers:
	*	Negative index to search up, positive index to search down. 
	*	Function considers all E8 bytes as 'call' instructsion, that would make for a valid call (to address within process-bounds).
	* 
	* OneBasedFuncIndex -> Index of a function we want to find, n-th sub_ in IDA starting from this MemAddress
	* IsWantedTarget -> Allows for the caller to pass a callback to verify, that the function at index n is the target we're looking for; else continue searching for a valid target.
	*/
	inline MemAddress GetRipRelativeCalledFunction(int32_t OneBasedFuncIndex, bool(*IsWantedTarget)(MemAddress CalledAddr) = nullptr) const
	{
		if (!Address || OneBasedFuncIndex == 0)
			return nullptr;

		const int32_t Multiply = OneBasedFuncIndex > 0 ? 1 : -1;

		/* Returns Index if FunctionIndex is positive, else -1 if the index is less than 0 */
		auto GetIndex = [=](int32_t Index) -> int32_t { return Index * Multiply; };

		constexpr int32_t RealtiveCallOpcodeCount = 0x5;

		int32_t NumCalls = 0;

		for (int i = 0; i < 0xFFF; i++)
		{
			const int32_t Index = GetIndex(i);

			/* If this isn't a call, we don't care about it and want to continue */
			if (Get<uint8_t>()[Index] != 0xE8)
				continue;

			const int32_t RelativeOffset = *reinterpret_cast<int32_t*>(Address + Index + 0x1 /* 0xE8 byte */);
			MemAddress RelativeCallTarget = Address + Index + RelativeOffset + RealtiveCallOpcodeCount;

			if (!IsInProcessRange(RelativeCallTarget))
				continue;

			if (++NumCalls == abs(OneBasedFuncIndex))
			{
				/* This is not the target we wanted, even tho it's at the right index. Decrement the index to the value before and check if the next call satisfies the custom-condition. */
				if (IsWantedTarget && !IsWantedTarget(RelativeCallTarget))
				{
					--NumCalls;
					continue;
				}

				return RelativeCallTarget;
			}
		}

		return nullptr;
	}

	/* Note: Unrealiable */
	inline MemAddress FindNextFunctionStart() const
	{
		if (!Address)
			return MemAddress(nullptr);

		uintptr_t FuncEnd = (uintptr_t)FindFunctionEnd();

		return FuncEnd % 0x10 != 0 ? FuncEnd + (0x10 - (FuncEnd % 0x10)) : FuncEnd;
	}
};

template<typename Type = const char*>
inline MemAddress FindByString(Type RefStr)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uintptr_t SearchStart = ImageBase;
	uintptr_t SearchRange = ImageSize;

	const auto [RDataSection, RDataSize] = GetSectionByName(ImageBase, ".rdata");
	const auto [TextSection, TextSize] = GetSectionByName(ImageBase, ".text");
	
	if (!RDataSection || !TextSection)
		return nullptr;

	uintptr_t StringAddress = NULL;

	const auto RetfStrLength = StrlenHelper(RefStr);

	for (int i = 0; i < RDataSize; i++)
	{
		if (StrnCmpHelper(RefStr, reinterpret_cast<Type>(RDataSection + i), RetfStrLength) == 0)
		{
			StringAddress = RDataSection + i;
			break;
		}
	}

	if (!StringAddress)
		return nullptr;

	for (int i = 0; i < TextSize; i++)
	{
		// opcode: lea
		const uint8_t CurrentByte = *reinterpret_cast<const uint8_t*>(TextSection + i);
		const uint8_t NextByte    = *reinterpret_cast<const uint8_t*>(TextSection + i + 0x1);

		if ((CurrentByte == 0x4C || CurrentByte == 0x48) && NextByte == 0x8D)
		{
			const uintptr_t StrPtr = ASMUtils::Resolve32BitRelativeLea(TextSection + i);

			if (StrPtr == StringAddress)
				return { TextSection + i };
		}
	}

	return nullptr;
}

inline MemAddress FindByWString(const wchar_t* RefStr)
{
	return FindByString<const wchar_t*>(RefStr);
}

/* Slower than FindByString */
template<bool bCheckIfLeaIsStrPtr = false, typename CharType = char>
inline MemAddress FindByStringInAllSections(const CharType* RefStr, uintptr_t StartAddress = 0x0, int32_t Range = 0x0)
{
	static_assert(std::is_same_v<CharType, char> || std::is_same_v<CharType, wchar_t>, "FindByStringInAllSections only supports 'char' and 'wchar_t', but was called with other type.");

	/* Stop scanning when arriving 0x10 bytes before the end of the memory range */
	constexpr int32_t OffsetFromMemoryEnd = 0x10;

	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	const uintptr_t ImageEnd = ImageBase + ImageSize;

	/* If the StartAddress is not default nullptr, and is out of memory-range */
	if (StartAddress != 0x0 && (StartAddress < ImageBase || StartAddress > ImageEnd))
		return nullptr;

	/* Add a few bytes to the StartAddress to prevent instantly returning the previous result */
	uint8_t* SearchStart = StartAddress ? (reinterpret_cast<uint8_t*>(StartAddress) + 0x5) : reinterpret_cast<uint8_t*>(ImageBase);
	DWORD SearchRange = StartAddress ? ImageEnd - StartAddress : ImageSize;

	if (Range != 0x0)
		SearchRange = min(Range, SearchRange);

	if ((StartAddress + SearchRange) >= ImageEnd)
		SearchRange -= OffsetFromMemoryEnd;

	const int32_t RefStrLen = StrlenHelper(RefStr);

	for (uintptr_t i = 0; i < SearchRange; i++)
	{
		// opcode: lea
		if ((SearchStart[i] == uint8_t(0x4C) || SearchStart[i] == uint8_t(0x48)) && SearchStart[i + 1] == uint8_t(0x8D))
		{
			const uintptr_t StrPtr = ASMUtils::Resolve32BitRelativeLea(reinterpret_cast<uintptr_t>(SearchStart + i));

			if (!IsInProcessRange(StrPtr))
				continue;

			if (StrnCmpHelper(RefStr, reinterpret_cast<const CharType*>(StrPtr), RefStrLen))
				return { SearchStart + i };

			if constexpr (bCheckIfLeaIsStrPtr)
			{
				const CharType* StrPtrContentFirst8Bytes = *reinterpret_cast<const CharType* const*>(StrPtr);

				if (!IsInProcessRange(StrPtrContentFirst8Bytes))
					continue;

				if (StrnCmpHelper(RefStr, StrPtrContentFirst8Bytes, RefStrLen))
					return { SearchStart + i };
			}
		}
	}

	return nullptr;
}

template<typename Type = const char*>
inline MemAddress FindUnrealExecFunctionByString(Type RefStr, void* StartAddress = nullptr)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uint8_t* SearchStart = StartAddress ? reinterpret_cast<uint8_t*>(StartAddress) : reinterpret_cast<uint8_t*>(ImageBase);
	DWORD SearchRange = ImageSize;

	const int32_t RefStrLen = StrlenHelper(RefStr);

	static auto IsValidExecFunctionNotSetupFunc = [](uintptr_t Address) -> bool
	{
		/* 
		* UFuntion construction functions setting up exec functions always start with these asm instructions:
		* sub rsp, 28h
		* 
		* In opcode bytes: 48 83 EC 28
		*/
		if (*reinterpret_cast<int32_t*>(Address) == 0x284883EC || *reinterpret_cast<int32_t*>(Address) == 0x4883EC28)
			return false;

		MemAddress AsAddress(Address);

		/* A signature specifically made for UFunctions-construction functions. If this signature is found we're in a function that we *don't* want. */
		if (AsAddress.RelativePattern("48 8B 05 ? ? ? ? 48 85 C0 75 ? 48 8D 15", 0x28) != nullptr)
			return false;

		return true;
	};

	for (uintptr_t i = 0; i < (SearchRange - 0x8); i += sizeof(void*))
	{
		const uintptr_t PossibleStringAddress = *reinterpret_cast<uintptr_t*>(SearchStart + i);
		const uintptr_t PossibleExecFuncAddress = *reinterpret_cast<uintptr_t*>(SearchStart + i + sizeof(void*));

		if (PossibleStringAddress == PossibleExecFuncAddress)
			continue;

		if (!IsInProcessRange(PossibleStringAddress) || !IsInProcessRange(PossibleExecFuncAddress))
			continue;

		if constexpr (std::is_same<Type, const char*>())
		{
			if (strncmp(reinterpret_cast<const char*>(RefStr), reinterpret_cast<const char*>(PossibleStringAddress), RefStrLen) == 0 && IsValidExecFunctionNotSetupFunc(PossibleExecFuncAddress))
			{
				// std::cout << "FoundStr ref: " << reinterpret_cast<const char*>(PossibleStringAddress) << "\n";

				return { PossibleExecFuncAddress };
			}
		}
		else
		{
			if (wcsncmp(reinterpret_cast<const wchar_t*>(RefStr), reinterpret_cast<const wchar_t*>(PossibleStringAddress), RefStrLen) == 0 && IsValidExecFunctionNotSetupFunc(PossibleExecFuncAddress))
			{
				// std::wcout << L"FoundStr wref: " << reinterpret_cast<const wchar_t*>(PossibleStringAddress) << L"\n";

				return { PossibleExecFuncAddress };
			}
		}
	}

	return nullptr;
}

/* Slower than FindByWString */
template<bool bCheckIfLeaIsStrPtr = false>
inline MemAddress FindByWStringInAllSections(const wchar_t* RefStr)
{
	return FindByStringInAllSections<bCheckIfLeaIsStrPtr, wchar_t>(RefStr);
}


namespace FileNameHelper
{
	inline void MakeValidFileName(std::string& InOutName)
	{
		for (char& c : InOutName)
		{
			if (c == '<' || c == '>' || c == ':' || c == '\"' || c == '/' || c == '\\' || c == '|' || c == '?' || c == '*')
				c = '_';
		}
	}
}
