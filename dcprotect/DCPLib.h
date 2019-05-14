#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <ctype.h>
#include <vector>

void WINAPI InitializeApplication(LPVOID hHandle, DWORD dwReason, LPVOID lpReserved);
extern std::vector<unsigned int> FUNCTION_START_ADDRLIST, FUNCTION_END_ADDRLIST, FUNCTION_ILT_OFFSETS, FUNCTION_PAGE_FLAGS;
extern std::vector<std::vector<unsigned int>> FUNCTION_PREV_INSTR_SET;
extern DWORD IltCollectionStartPtr;

#define MASM __asm

#ifndef VH_CALL_LAST
#define VH_CALL_LAST 0
#endif

#ifndef VH_CALL_FIRST
#define VH_CALL_FIRST 1
#endif

#ifndef NOP
#define NOP __asm { nop }
#define NOP_WORD NOP NOP
#define NOP_DWORD NOP_WORD NOP_WORD
#define NOP_10 NOP NOP NOP NOP NOP NOP NOP NOP NOP NOP
#endif

#ifndef PROLOGMARKER
#define PROLOGMARKER	_asm _emit 0CAh \
						_asm _emit 0FEh \
						_asm _emit 0BEh \
						_asm _emit 0EFh 
#endif

#ifndef EPILOGMARKER
#define EPILOGMARKER	_asm _emit 0BEh \
						_asm _emit 0EFh \
						_asm _emit 0CAh \
						_asm _emit 0FEh 
#endif

#ifndef PROLOGMPROT
#define PROLOGMPROT		DWORD *lpflOldProtect = (DWORD *)malloc(4);\
						VirtualProtect((LPVOID)FUNCTION_START_ADDRLIST.back(), FUNCTION_END_ADDRLIST.back() - FUNCTION_START_ADDRLIST.back(), PAGE_EXECUTE_READWRITE, lpflOldProtect);
#endif

#ifndef EPILOGMPROT
#define EPILOGMPROT		VirtualProtect((LPVOID)FUNCTION_START_ADDRLIST.back(), FUNCTION_END_ADDRLIST.back() - FUNCTION_START_ADDRLIST.back(), PAGE_EXECUTE_READ, lpflOldProtect);\
						free(lpflOldProtect);
#endif

#ifndef PROLOGSAVEADDR 
#define PROLOGSAVEADDR	unsigned int localFunctionStartAddr, localFunctionEndAddr, localFunctionIltAddr;\
						std::vector<unsigned int> dcpPrevInstr;\
						MASM\
						{\
							_asm mov dword ptr localFunctionStartAddr, offset DCPFunctionStart\
							_asm mov dword ptr localFunctionEndAddr, offset DCPFunctionEnd\
							_asm mov dword ptr localFunctionIltAddr, 0ACEFFECAh\
						}\
						printf("\t\t1FS=0x%08X\n", FUNCTION_START_ADDRLIST.empty() ? 0: FUNCTION_START_ADDRLIST.back());\
						printf("\t\tFSL=0x%08X\n", localFunctionStartAddr);\
						FUNCTION_START_ADDRLIST.push_back(localFunctionStartAddr);\
						printf("\t\t2FS=0x%08X\n", FUNCTION_START_ADDRLIST.back());\
						FUNCTION_END_ADDRLIST.push_back(localFunctionEndAddr);\
						FUNCTION_ILT_OFFSETS.push_back(localFunctionIltAddr);\
						FUNCTION_PREV_INSTR_SET.push_back(dcpPrevInstr);
#endif

#ifndef EPILOGSAVEADDR
#define EPILOGSAVEADDR	FUNCTION_START_ADDRLIST.pop_back();\
						FUNCTION_END_ADDRLIST.pop_back();\
						FUNCTION_ILT_OFFSETS.pop_back();\
						FUNCTION_PREV_INSTR_SET.pop_back();
#endif

#ifndef DCPFunctionProlog
#define DCPFunctionProlog	NOP\
							PROLOGSAVEADDR\
							PROLOGMPROT\
							MASM\
							{\
								_asm jmp short DCPPrologMarker\
								PROLOGMARKER\
								_asm DCPPrologMarker:\
								_asm pushfd\
								_asm or dword ptr [esp], 000000100h\
								_asm popfd\
								_asm nop\
								_asm DCPFunctionStart:\
							}
#endif

#ifndef DCPFunctionEpilog
#define DCPFunctionEpilog	MASM\
							{\
								_asm DCPFunctionEnd:\
								_asm nop\
								_asm jmp short DCPEpilogMarker\
								EPILOGMARKER\
								_asm DCPEpilogMarker:\
							}\
							EPILOGMPROT\
							EPILOGSAVEADDR
#endif