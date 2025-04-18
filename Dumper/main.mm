
#include <iostream>
#include <chrono>
#include <fstream>
#include <thread>
#include <chrono>
#include <format>

#include "Generators/CppGenerator.h"
#include "Generators/MappingGenerator.h"
#include "Generators/IDAMappingGenerator.h"
#include "Generators/DumpspaceGenerator.h"

#include "Generators/Generator.h"

#import <Foundation/Foundation.h>


template<typename... Args>
inline void LogMsg(const std::string& Fmt, Args&&... args)
{
    std::string formatted = std::format(Fmt, std::forward<Args>(args)...);
    NSLog(@"%s", formatted.c_str());
}


using namespace std::chrono_literals;

void MainThread(void)
{
    std::this_thread::sleep_for(15s);
    
	auto t_1 = std::chrono::high_resolution_clock::now();

	LogMsg("Started Generation [Dumper-7]!\n");

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

    LogMsg("GameName: {}\n", Settings::Generator::GameName);
    LogMsg("GameVersion: {}\n\n", Settings::Generator::GameVersion);


	Generator::Generate<CppGenerator>();
	Generator::Generate<MappingGenerator>();
	Generator::Generate<IDAMappingGenerator>();
	Generator::Generate<DumpspaceGenerator>();


	auto t_C = std::chrono::high_resolution_clock::now();

	auto ms_int_ = std::chrono::duration_cast<std::chrono::milliseconds>(t_C - t_1);
	std::chrono::duration<double, std::milli> ms_double_ = t_C - t_1;

    LogMsg("\n\nGenerating SDK took ({})ms)\n\n\n", ms_double_.count());
}

__attribute__((constructor))
void entry(void)
{
    std::thread DumperThread(MainThread);
    DumperThread.detach();
}
