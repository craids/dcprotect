#include "DCPatcher.h"

using namespace std;

int main(int argc, char* argv[])
{	
	string oldExecFile = "D:\\dcprotect\\Release\\dcprotect.exe";
	string execFile = "D:\\dcprotect\\Release\\dcprotect.patched.exe";
	DCPGflCopyFile(oldExecFile, execFile);
	printf("Patched File Copy created from %s.\n", oldExecFile.c_str());

	DCPMarkerInfo fpi;
	
	vector<byte> buf = DCPGflReadFile(execFile);
	vector<unsigned int> iltPtrPositions = DCPMkrGetIltAddressPos(buf);
	vector<unsigned int> prologPositions = DCPMkrGetFunctionPrologPos(buf);
	vector<unsigned int> epilogPositions = DCPMkrGetFunctionEpilogPos(buf);
	vector<unsigned int> funcIltOffsetPositions = DCPMkrGetFunctionIltOffsetPos(buf);
	vector<vector<unsigned int>> parallelSet;
	parallelSet.push_back(funcIltOffsetPositions);
	parallelSet.push_back(prologPositions);
	parallelSet.push_back(epilogPositions);
	
	PeLib::PeFile32* pe = (PeLib::PeFile32 *)PeLib::openPeFile(execFile);
	DCPGflPrintPeInformation(pe);
	PeLib::PeHeader32 peh = pe->peHeader();

	printf("%d function boundary markers found!\n", prologPositions.size() + epilogPositions.size() + funcIltOffsetPositions.size());
	printf("Sanity Check:\n");
	bool equSize = DCPGflCheckParallelVectorSizeEquality(parallelSet);
	bool addrOrder = DCPGflCheckParallelVectorSortedOrder(parallelSet);
	bool iltmkUniq = iltPtrPositions.size() == 1;
	printf("\tMarker Set...\t%s!\n", equSize ? "OK" : "ERROR");
	printf("\tMarker Order...\t%s!\n", addrOrder ? "OK" : "ERROR");
	printf("\tUnique ILT...\t%s!\n\n", iltmkUniq ? "OK" : "ERROR");
	if(!addrOrder || !equSize || !iltmkUniq)
	{
		printf("Marker set/orders are screwed up! Did someone tamper with the library?\n");
		system("PAUSE");
		return -1;
	}
	DCPGflPrintMarkerData(peh, iltPtrPositions, fpi.IltPtrMarker, "GlobalIltMkr", false);
	printf("\n");
	vector<DCPSection> dcpsc = DCPMkrGroupBySection(funcIltOffsetPositions, prologPositions, epilogPositions);
	ILTSet iltGlobal;

	for(unsigned int i = 0; i < dcpsc.size(); i++)
	{
		DCPGflPrintSectionData(peh, dcpsc.at(i));
		vector<byte> code = DCPGflGetSectionCode(buf, dcpsc.at(i));
		dcpsc.at(i).InstructionSizes = DCPAsmGetInstructionSize(code);

		ILT iltInstance;
		for(unsigned int j = 0; j < dcpsc.at(i).InstructionSizes.size(); j++)
		{
			ILTEntry iltEntryInstance;
			iltEntryInstance.InstructionLength = dcpsc.at(i).InstructionSizes.at(j);
			iltInstance.AppendEntry(iltEntryInstance);
		}
		dcpsc.at(i).FunctionIltRva = iltGlobal.GetTableRva(iltGlobal.GetNumberOfTables());
		printf("FunctionIltRva=0x%08X\n\n", dcpsc.at(i).FunctionIltRva);
		iltGlobal.AppendTable(iltInstance);
	}
	printf("\n");
	DWORD relocRva, relocSize, relocRawSize;
	DCPPelGetRelocDirMetadata(buf, peh, &relocRva, &relocSize, &relocRawSize);
	printf("Relocations Directory RVA: 0x%08X (DataSize=0x%08X,RawSize=0x%08X)\n", relocRva, relocSize, relocRawSize);
	printf("Global ILT Pointer VA: 0x%08X\n", peh.rvaToVa(relocRva + relocSize));
	printf("ILT Collection Size is 0x%X\n", iltGlobal.GetNumberOfBytes());

	// Patching and writing
	DCPIltWriteIltCollection(&buf, peh.rvaToOffset(relocRva + relocSize), DCPIltCollectionAsBytes(iltGlobal));
	DCPMkrPatchMarker(&buf, iltPtrPositions.at(0) + ILT_ADDR_OFFSET, peh.rvaToVa(relocRva + relocSize), false); // Patch Global ILT
	for(unsigned int i = 0; i < dcpsc.size(); i++) // Patch Local ILT RVA and encrypt code per section
	{
		DWORD codeSize = (dcpsc.at(i).EpilogMarkerOffset + PATCH_END_OFFSET) - (dcpsc.at(i).PrologMarkerOffset + PATCH_START_OFFSET);
		DCPMkrPatchMarker(&buf, dcpsc.at(i).IltPosOffset, dcpsc.at(i).FunctionIltRva, false);
		printf("Encrypting code at 0x%08X for %u bytes\n", dcpsc.at(i).PrologMarkerOffset + PATCH_START_OFFSET, codeSize);
		DCPMkrEncryptSectionCode(&buf, dcpsc.at(i).PrologMarkerOffset + PATCH_START_OFFSET, codeSize);
	}
	DCPGflWriteFile(execFile, buf);
	system("pause");
	return 0;
}

