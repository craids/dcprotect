#include "pespec/PeLib.h"
#include "DCPStructs.h"
#include <Windows.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <math.h>
#include "disasm/distorm.h"

using namespace std;
 
vector<byte> DCPGflReadFile(string filename);
void DCPGflWriteFile(string filename, vector<byte> fileContents);
void DCPGflCopyFile(string oldFile, string newFile);
void DCPGflPrintPeInformation(PeLib::PeFile32* pe);
void DCPGflPrintMarkerData(PeLib::PeHeader32 peh, vector<unsigned int> ptrPosCollection, vector<byte> markerBytes, string desc, bool numbered);
void DCPGflPrintSectionData(PeLib::PeHeader32 peh, DCPSection dcps);
vector<byte> DCPGflGetSectionCode(vector<byte> execFile, DCPSection dcps);
vector<unsigned int> DCPGflFindNeedleInHaystack(vector<byte> haystack, vector<byte> needle);
void DCPGflSortVectorElements(vector<unsigned int>* vec);
bool DCPGflCheckParallelVectorSizeEquality(vector<vector<unsigned int>> col);
bool DCPGflCheckParallelVectorSortedOrder(vector<vector<unsigned int>> col);
vector<byte> DCPGflConvertToLittleByteEndian(DWORD beDword);
vector<byte> DCPGflConvertToLittleByteEndian(WORD beWord);
DWORD DCPGflVectorGetDword(vector<byte> buf, DWORD offset);
WORD DCPGflVectorGetWord(vector<byte> buf, DWORD offset);
vector<byte> DCPGflDwordAsVector(DWORD dw);
vector<byte> DCPAsmGetInstructionSize(vector<byte> vbuf);
vector<DCPSection> DCPMkrGroupBySection(vector<unsigned int> locIltMkrPos, vector<unsigned int> prologMkrPos, vector<unsigned int> epilogMkrPos);
vector<unsigned int> DCPMkrGetFunctionPrologPos(vector<byte> buf);
vector<unsigned int> DCPMkrGetFunctionEpilogPos(vector<byte> buf);
vector<unsigned int> DCPMkrGetFunctionIltOffsetPos(vector<byte> buf);
vector<unsigned int> DCPMkrGetIltAddressPos(vector<byte> buf);
void DCPMkrPatchMarker(vector<byte> *buf, DWORD offset, DWORD newBytes, bool bigEndian);
void DCPMkrEncryptSectionCode(vector<byte> *buf, DWORD offset, DWORD size);
vector<byte> DCPIltCollectionAsBytes(ILTSet iltCollection);
void DCPIltWriteIltCollection(vector<byte> *buf, DWORD offset, vector<byte> iltCollectionBytes);
void DCPPelGetRelocDirMetadata(vector<byte> fileBuf, PeLib::PeHeader32 peh, DWORD *iddRelocRva, DWORD *iddRelocSize, DWORD *relocRawSize);

