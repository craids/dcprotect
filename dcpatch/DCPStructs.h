#include <Windows.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

#define MASM _asm

#define MAX_INSTRUCTIONS (1000)

#define FUNCTION_SUCCESS 0
#define FUNCTION_FAILURE_GENERIC -1

#define PATCH_START_OFFSET 14
#define PATCH_END_OFFSET -3
#define ILT_ADDR_OFFSET 6

#define _PROLOGMARKER {0xCA, 0xFE, 0xBE, 0xEF}
#define _EPILOGMARKER {0xBE, 0xEF, 0xCA, 0xFE}
#define _ILTPTRMARKER {0xDE, 0xAD, 0xBE, 0xEF}
#define _FPTILTMARKER {0xCA, 0xFE, 0xEF, 0xAC}

using namespace std;

typedef struct _DCPMarkerInfo
{
	vector<byte>	PrologMarker;
	vector<byte>	EpilogMarker;
	vector<byte>	IltPtrMarker;
	vector<byte>	LocalIltPtrMarker;

	_DCPMarkerInfo()
	{
		byte PROLOGMARKER[] = _PROLOGMARKER;
		byte EPILOGMARKER[] = _EPILOGMARKER;
		byte ILTPTRMARKER[] = _ILTPTRMARKER;
		byte FPTILTMARKER[] = _FPTILTMARKER;
		PrologMarker = vector<byte>(PROLOGMARKER, PROLOGMARKER + sizeof(PROLOGMARKER));
		EpilogMarker = vector<byte>(EPILOGMARKER, EPILOGMARKER + sizeof(EPILOGMARKER));
		IltPtrMarker = vector<byte>(ILTPTRMARKER, ILTPTRMARKER + sizeof(ILTPTRMARKER));
		LocalIltPtrMarker = vector<byte>(FPTILTMARKER, FPTILTMARKER + sizeof(FPTILTMARKER));
	};
} DCPMarkerInfo;

typedef struct _DCPSection
{
	vector<byte> PrologMarker;
	vector<byte> EpilogMarker;
	vector<byte> IltRvaMarker;
	vector<byte> InstructionSizes;
	DWORD FunctionIltRva;
	DWORD PrologMarkerOffset;
	DWORD EpilogMarkerOffset;
	DWORD IltPosOffset;

	_DCPSection()
	{
		DCPMarkerInfo fpi;
		PrologMarker = fpi.PrologMarker;
		EpilogMarker = fpi.EpilogMarker;
		IltRvaMarker = fpi.LocalIltPtrMarker;
	};
} DCPSection;

typedef struct _DCP_INSTRUCTION_LENGTH_TABLE_ENTRY
{
	BYTE InstructionLength;
} ILTEntry;

typedef struct _DCP_INSTRUCTION_LENGTH_TABLE 
{
private:
	vector<ILTEntry> ILTInstructions;
	BYTE Terminator;

public:
	_DCP_INSTRUCTION_LENGTH_TABLE()
	{
		Terminator = 0xFF;
		ILTInstructions.clear();
	};

	void AppendEntry(ILTEntry ilte)
	{
		ILTInstructions.push_back(ilte);
	};

	ILTEntry RemoveEntry()
	{
		ILTEntry ilte = ILTInstructions.back();
		ILTInstructions.pop_back();
		return ilte;
	};

	ILTEntry GetEntry(unsigned int idx)
	{
		return ILTInstructions.at(idx);
	};

	DWORD GetNumberOfEntries()
	{
		return ILTInstructions.size();
	};

	BYTE GetTerminatingByte()
	{
		return Terminator;
	};

	BYTE GetInstructionLength(DWORD entryNum)
	{
		return ILTInstructions.at(entryNum).InstructionLength;
	};

	DWORD GetInstructionLengthTotal()
	{
		DWORD total = 0; 
		for(unsigned int i = 0; i < ILTInstructions.size(); i++)
			total += ILTInstructions.at(i).InstructionLength;
		return total;
	};

	DWORD GetByteCount()
	{
		DWORD size = 0;
		for(unsigned int i = 0; i < ILTInstructions.size(); i++)
			size += sizeof(ILTInstructions.at(i).InstructionLength);
		return sizeof(Terminator) + size;
	};
} ILT;

typedef struct _DCP_INSTUCTION_LENGTH_TABLE_SET
{
private:
	vector<ILT> ILTCollection;

public:
	_DCP_INSTUCTION_LENGTH_TABLE_SET()
	{
		ILTCollection.clear();
	};

	void AppendTable(ILT ilt)
	{
		ILTCollection.push_back(ilt);
	};

	ILT RemoveTable()
	{
		ILT ilt = ILTCollection.back();
		ILTCollection.pop_back();
		return ilt;
	};

	ILT GetTable(unsigned int idx)
	{
		return ILTCollection.at(idx);
	};

	DWORD GetNumberOfTables()
	{
		return ILTCollection.size();
	};

	DWORD GetNumberOfBytes()
	{
		DWORD szBytes = 0;
		for(unsigned int i = 0; i < ILTCollection.size(); i++)
			szBytes += ILTCollection.at(i).GetByteCount();
		return szBytes;
	};

	DWORD GetTableRva(unsigned int idx)
	{
		DWORD rva = 0;
		for(unsigned int i = 0; i < idx; i++)
			rva += ILTCollection.at(i).GetByteCount();
		return rva;
	};
} ILTSet;