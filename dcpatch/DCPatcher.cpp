#include "DCPatcher.h"

using namespace std;

DCPMarkerInfo fpi;

vector<byte> DCPGflReadFile(string filename)
{
	vector<byte> buf;
	unsigned int filesize = 0;
	fstream fin(filename, ios::in | ios::binary);
	while(!fin.eof())
		buf.push_back((byte)fin.get());
	fin.close();
	return buf;
}

void DCPGflWriteFile(string filename, vector<byte> fileContents)
{
	fstream fout(filename, ios::out | ios::binary);
	for(unsigned int i = 0; i < fileContents.size(); i++)
		fout.put(fileContents.at(i));
	fout.close();
}

void DCPGflCopyFile(string oldFile, string newFile)
{
	ifstream oldf(oldFile, ios::in | ios::binary);
	ofstream newf(newFile, ios::out | ios::binary);
	while(!oldf.eof())
		newf.put(oldf.get());
	oldf.close();
	newf.close();
}

vector<unsigned int> DCPGflFindNeedleInHaystack(vector<byte> haystack, vector<byte> needle)
{
	vector<unsigned int> needlePositions;
	for(unsigned int i = 0; i < haystack.size() - needle.size(); i++)
	{
		bool found = true;
		for(unsigned int j = 0; j < needle.size(); j++)
		{
			found = (haystack.at(i+j) == needle.at(j));
			if(!found)
				break;
		}
		if(found)
			needlePositions.push_back(i);
	}
	return needlePositions;
}

void DCPGflPrintPeInformation(PeLib::PeFile32* pe)
{
	pe->readMzHeader();
	pe->readPeHeader();
	pe->readBoundImportDirectory();
	pe->readDebugDirectory();
	pe->readExportDirectory();
	pe->readIatDirectory();
	pe->readImportDirectory();
	pe->readRelocationsDirectory();
	pe->readResourceDirectory();
	pe->readTlsDirectory();
	PeLib::PeHeader32 peh = pe->peHeader();
	printf("-------------------------------------------------------------------------------\n");
	printf("Portable Executable Information\n");
	printf("-------------------------------------------------------------------------------\n");
	printf("File Name:\t%s\n", pe->getFileName().c_str());
	printf("Architecture:\t%d bit\n", pe->getBits());
	printf("Sections:\t%d\n", peh.getNumberOfSections());
	printf("Image Base:\t0x%08X\n", peh.getImageBase());
	printf("Code Section:\t0x%08X\n", peh.getImageBase() + peh.getBaseOfCode());
	printf("Entry Point:\t0x%08X\n", peh.getImageBase() + peh.getAddressOfEntryPoint());
	printf("Last Section:\t%s\n", peh.getSectionName(peh.getNumberOfSections() - 1).c_str());
	printf("-------------------------------------------------------------------------------\n");
	if(peh.getNumberOfSections() - 1 != peh.getSectionWithRva(peh.getIddBaseRelocRva()))
	{
		printf("Die! The last PE section must be the Relocation Directory in order to be patchable!\n");
		system("PAUSE");
		ExitProcess(-1);
	}
}

void DCPGflPrintMarkerData(PeLib::PeHeader32 peh, vector<unsigned int> ptrPosCollection, vector<byte> markerBytes, string desc, bool numbered)
{
	for(unsigned int i = 0; i < ptrPosCollection.size(); i++)
	{
		uint32_t offset = ptrPosCollection.at(i);
		uint32_t va = peh.offsetToVa(offset);
		string section = peh.getSectionName(peh.getSectionWithOffset(offset));
		char buf[10] = "";
		_itoa_s(i+1, buf, 10);
		string num(buf, buf + strlen(buf));
		numbered ? num.size() : num.clear();
		printf("%s %s\t@ %s[0x%08X]: ( ", desc.c_str(), num.c_str(), section.c_str(), va);
		for(unsigned int j = 0; j < markerBytes.size(); j++)
			printf("0x%02X ", markerBytes.at(j));
		printf(")\n");
	}
}

void DCPGflPrintSectionData(PeLib::PeHeader32 peh, DCPSection dcps)
{
	DWORD protStart = dcps.PrologMarkerOffset + PATCH_START_OFFSET;
	DWORD protEnd = dcps.EpilogMarkerOffset + PATCH_END_OFFSET;
	printf("DCPSection Data:\tFILE_OFFSET\t| REL_VIRTADDR\t| VIRTADDR\n");
	printf("\tILT_OFFSET:\t0x%08X\t| 0x%08X\t| 0x%08X\n", dcps.IltPosOffset, peh.offsetToRva(dcps.IltPosOffset), peh.offsetToVa(dcps.IltPosOffset));
	printf("\tPROT_START:\t0x%08X\t| 0x%08X\t| 0x%08X\n", protStart, peh.offsetToRva(protStart), peh.offsetToVa(protStart));
	printf("\tPROT_END:\t0x%08X\t| 0x%08X\t| 0x%08X\n",	protEnd, peh.offsetToRva(protEnd), peh.offsetToVa(protEnd));
}

vector<byte> DCPGflGetSectionCode(vector<byte> execFile, DCPSection dcps)
{
	vector<byte> code;
	DWORD codeStart = dcps.PrologMarkerOffset + PATCH_START_OFFSET;
	DWORD codeEnd = dcps.EpilogMarkerOffset + PATCH_END_OFFSET;
	for(unsigned int i = codeStart; i <= codeEnd; i++)
		code.push_back(execFile.at(i));
	return code;
}

void DCPGflSortVectorElements(vector<unsigned int>* vec)
{
	sort((*vec).begin(), (*vec).end());
}

bool DCPGflCheckParallelVectorSizeEquality(vector<vector<unsigned int>> col)
{
	bool equal = true;
	if(col.size() <= 1)
		return true;
	for(unsigned int i = 0; i < col.size() - 1; i++)
		equal &= col.at(i).size() == col.at(i+1).size();
	return equal;
}

bool DCPGflCheckParallelVectorSortedOrder(vector<vector<unsigned int>> col)
{
	bool order = true;
	if(!DCPGflCheckParallelVectorSizeEquality(col))
		return false;
	if(col.size() <= 1)
		return true;
	for(unsigned int i = 0; i < col.size(); i++)
		DCPGflSortVectorElements(&col.at(i));
	for(unsigned int i = 0; i < col.size() - 1; i++)
		for(unsigned int j = 0; j < col.at(i).size(); j++)
			order &= col.at(i).at(j) < col.at(i+1).at(j);
	return order;
}

vector<byte> DCPGflConvertToLittleByteEndian(DWORD beDword)
{
	vector<byte> leDword;
	leDword.push_back((byte)(beDword));
	leDword.push_back((byte)((beDword >> 8) & 0xFF));
	leDword.push_back((byte)((beDword >> 16) & 0xFF));
	leDword.push_back((byte)((beDword >> 24) & 0xFF));
	return leDword;
}

vector<byte> DCPGflConvertToLittleByteEndian(WORD beWord)
{
	vector<byte> leWord;
	leWord.push_back((byte)(beWord));
	leWord.push_back((byte)((beWord >> 8) & 0xFF));
	return leWord;
}

vector<byte> DCPGflDwordAsVector(DWORD dw)
{
	vector<byte> dwv;
	dwv.push_back((byte)((dw >> 24) & 0xFF));
	dwv.push_back((byte)((dw >> 16) & 0xFF));
	dwv.push_back((byte)((dw >> 8) & 0xFF));
	dwv.push_back((byte)dw);
	return dwv;
}

DWORD DCPGflVectorGetDword(vector<byte> buf, DWORD offset)
{
	DWORD t = 0;
	for(unsigned int i = 0; i < 4; i++)
		t += (buf.at(i + offset) << (i * sizeof(DWORD) * 2));
	return t;
}

WORD DCPGflVectorGetWord(vector<byte> buf, DWORD offset)
{
	WORD t = 0;
	for(unsigned int i = 0; i < 2; i++)
		t += (buf.at(i + offset) << (i * sizeof(WORD) * 2));
	return t;
}

vector<byte> DCPAsmGetInstructionSize(vector<byte> vbuf)
{
	vector<byte> instructionSizes;
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = 0;

	DWORD bufsize = vbuf.size();
	byte *buf = (byte *)malloc(vbuf.size());
	copy(vbuf.begin(), vbuf.begin() + vbuf.size(), buf);

	while(true)
	{
		res = distorm_decode(offset, (unsigned char *)buf, bufsize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR)
		{
			printf("Buffer Input Error! Process halting...");
			free(buf);
			ExitProcess(-4);
		}

		//for (int i = 0; i < decodedInstructionsCount; i++)
		//	printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p); 

		if (res == DECRES_SUCCESS) break; // All instructions were decoded.
		else if (decodedInstructionsCount == 0) break;

		next = (unsigned long)(decodedInstructions[decodedInstructionsCount-1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount-1].size;
		// Advance ptr and recalc offset.
		buf += next;
		bufsize -= next;
		offset += next;
	}
	for (unsigned int i = 0; i < decodedInstructionsCount; i++)
		instructionSizes.push_back((byte)decodedInstructions[i].size);
	free(buf);
	return instructionSizes;
}

vector<DCPSection> DCPMkrGroupBySection(vector<unsigned int> locIltMkrPos, vector<unsigned int> prologMkrPos, vector<unsigned int> epilogMkrPos)
{
	vector<vector<unsigned int>> col;
	col.push_back(locIltMkrPos);
	col.push_back(prologMkrPos);
	col.push_back(epilogMkrPos);
	bool sane = DCPGflCheckParallelVectorSortedOrder(col);
	if(!sane)
	{
		printf("Fatal Error! Markers cannot exist in a sorted parallel order!\n");
		system("PAUSE");
		ExitProcess(-1);
	}
	vector<DCPSection> dcpsc;
	for(unsigned int i = 0; i < locIltMkrPos.size(); i++)
	{
		DCPSection dcps;
		dcps.IltPosOffset = locIltMkrPos.at(i);
		dcps.PrologMarkerOffset = prologMkrPos.at(i);
		dcps.EpilogMarkerOffset = epilogMkrPos.at(i);
		dcpsc.push_back(dcps);
	}
	return dcpsc;
}

vector<unsigned int> DCPMkrGetFunctionPrologPos(vector<byte> buf)
{
	return DCPGflFindNeedleInHaystack(buf, fpi.PrologMarker);
}

vector<unsigned int> DCPMkrGetFunctionEpilogPos(vector<byte> buf)
{
	return DCPGflFindNeedleInHaystack(buf, fpi.EpilogMarker);
}

vector<unsigned int> DCPMkrGetFunctionIltOffsetPos(vector<byte> buf)
{
	return DCPGflFindNeedleInHaystack(buf, fpi.LocalIltPtrMarker);
}

vector<unsigned int> DCPMkrGetIltAddressPos(vector<byte> buf)
{
	return DCPGflFindNeedleInHaystack(buf, fpi.IltPtrMarker);
}

void DCPMkrPatchMarker(vector<byte> *buf, DWORD offset, DWORD newBytes, bool bigEndian)
{
	vector<byte> vnewBytes = bigEndian ? DCPGflDwordAsVector(newBytes) : DCPGflConvertToLittleByteEndian(newBytes);
	for(unsigned int i = offset; i < offset + sizeof(newBytes); i++)
		(*buf)[i] = vnewBytes.at(i - offset);
}

void DCPMkrEncryptSectionCode(vector<byte> *buf, DWORD offset, DWORD size)
{
	for(unsigned int i = offset; i < offset + size; i++)
		(*buf)[i] ^= 0xAA;
}

vector<byte> DCPIltCollectionAsBytes(ILTSet iltCollection)
{
	vector<byte> iltCollectionBytes;
	for(unsigned int i = 0; i < iltCollection.GetNumberOfTables(); i++)
	{
		for(unsigned int j = 0; j < iltCollection.GetTable(i).GetNumberOfEntries(); j++)
			iltCollectionBytes.push_back(iltCollection.GetTable(i).GetEntry(j).InstructionLength);
		iltCollectionBytes.push_back(iltCollection.GetTable(i).GetTerminatingByte());
	}
	return iltCollectionBytes;
}

void DCPIltWriteIltCollection(vector<byte> *buf, DWORD offset, vector<byte> iltCollectionBytes)
{
	for(unsigned int i = offset; i < offset + iltCollectionBytes.size(); i++)
		(*buf)[i] = iltCollectionBytes.at(i - offset);
}

void DCPPelGetRelocDirMetadata(vector<byte> fileBuf, PeLib::PeHeader32 peh, DWORD *iddRelocRva, DWORD *iddRelocSize, DWORD *relocRawSize)
{
	*iddRelocRva = peh.getIddBaseRelocRva();
	*iddRelocSize = peh.getIddBaseRelocSize();
	*relocRawSize = peh.getSizeOfRawData(peh.getSectionWithRva(*iddRelocRva));
}
