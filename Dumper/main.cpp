
#include <iostream>
#include <chrono>
#include <fstream>
#include <thread>

#include "Generators/CppGenerator.h"
#include "Generators/MappingGenerator.h"
#include "Generators/IDAMappingGenerator.h"
#include "Generators/DumpspaceGenerator.h"

#include "Generators/Generator.h"


void MainThread(void)
{
	auto t_1 = std::chrono::high_resolution_clock::now();

	std::cout << "Started Generation [Dumper-7]!\n";

	Generator::InitEngineCore();
	Generator::InitInternal();

	if (Settings::Generator::GameName.empty() && Settings::Generator::GameVersion.empty())
	{
		// Only Possible in Main()
		FString Name;
		FString Version;
		UEClass Kismet = ObjectArray::FindClassFast("KismetSystemLibrary");
		UEFunction GetGameName = Kismet.GetFunction("KismetSystemLibrary", "GetGameName");
		UEFunction GetEngineVersion = Kismet.GetFunction("KismetSystemLibrary", "GetEngineVersion");

		Kismet.ProcessEvent(GetGameName, &Name);
		Kismet.ProcessEvent(GetEngineVersion, &Version);

		Settings::Generator::GameName = Name.ToString();
		Settings::Generator::GameVersion = Version.ToString();
	}

	std::cout << "GameName: " << Settings::Generator::GameName << "\n";
	std::cout << "GameVersion: " << Settings::Generator::GameVersion << "\n\n";

	Generator::Generate<CppGenerator>();
	Generator::Generate<MappingGenerator>();
	Generator::Generate<IDAMappingGenerator>();
	Generator::Generate<DumpspaceGenerator>();


	auto t_C = std::chrono::high_resolution_clock::now();

	auto ms_int_ = std::chrono::duration_cast<std::chrono::milliseconds>(t_C - t_1);
	std::chrono::duration<double, std::milli> ms_double_ = t_C - t_1;

	std::cout << "\n\nGenerating SDK took (" << ms_double_.count() << "ms)\n\n\n";
}

__attribute__((constructor))
void entry(void)
{
    std::thread DumperThread(MainThread);
    DumperThread.detach();
}
