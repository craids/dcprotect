#include "DCPLib.h"

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_entry")
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK tls_entry = InitializeApplication;
#pragma data_seg()

std::vector<unsigned int> FUNCTION_START_ADDRLIST, FUNCTION_END_ADDRLIST, FUNCTION_ILT_OFFSETS, FUNCTION_PAGE_FLAGS;
std::vector<std::vector<unsigned int>> FUNCTION_PREV_INSTR_SET;
DWORD IltCollectionStartPtr;

/*
	VEH Handler that is installed at the top of the vector.
	No guarantee that this VEH will be the first to be called
	as user may install own VEH at top of the vector.
	Hence user MUST be advised against using AddVectoredExceptionHandler(1, &fnHandle).
	User should add VEH using AddVectoredContinueHandler.
*/
LONG WINAPI DCPVEHFunctionEncapsulation(PEXCEPTION_POINTERS ExceptionInfo)
{
	PEXCEPTION_RECORD ExRecord = ExceptionInfo->ExceptionRecord;
	PCONTEXT CtxRecord = ExceptionInfo->ContextRecord;
	DWORD ExThrownCode = ExRecord->ExceptionCode;
	DWORD InstructionPointer = CtxRecord->Eip;

	switch(ExThrownCode)
	{
	case EXCEPTION_SINGLE_STEP:
		// if InstructionPointer is not the start address, encrypt the previous instruction.
		if(!(InstructionPointer < FUNCTION_START_ADDRLIST.back() || InstructionPointer > FUNCTION_END_ADDRLIST.back())) // EIP must not be a call/jmp address out of func
		{
			PBYTE functionIlt = (PBYTE)(IltCollectionStartPtr + FUNCTION_ILT_OFFSETS.back());
			printf("\t[*] EXCEPTION_SINGLE_STEP: eip=0x%08X\n", InstructionPointer);
			printf("\t--> FS=0x%08X, FE=0x%08X, IP=0x%08X ", FUNCTION_START_ADDRLIST.back(), FUNCTION_END_ADDRLIST.back(), InstructionPointer);

			// Decrypt previous instruction
			if(!FUNCTION_PREV_INSTR_SET.back().empty())
			{
				PBYTE prevInstructionPointer = (PBYTE)(FUNCTION_PREV_INSTR_SET.back().back());
				BYTE InstructionLength = (BYTE)(*((PDWORD)(IltCollectionStartPtr + FUNCTION_ILT_OFFSETS.back() + FUNCTION_PREV_INSTR_SET.back().size() - 1)));
				for(byte b = 0; b < InstructionLength; b++)
					*(prevInstructionPointer + b) ^= 0xAA;
			}

			// If it is the last instruction, destroy the PrevInstrSet tracker for this function.
			if(InstructionPointer == FUNCTION_END_ADDRLIST.back())
			{
				printf("(LAST EXCEPTION!)\n");
				printf("\t|------> RANGE: {0x%08X ~ 0x%08X), ILTOFF: 0x%08X", FUNCTION_START_ADDRLIST.back(), FUNCTION_END_ADDRLIST.back(), FUNCTION_ILT_OFFSETS.back());
			}
			// Else, add EIP to the PrevInstrSet for tracking and decrypt instruction at EIP.
			else
			{
				PBYTE pInstructionPointer = (PBYTE)InstructionPointer;
				BYTE InstructionLength = (BYTE)(*((PDWORD)(IltCollectionStartPtr + FUNCTION_ILT_OFFSETS.back() + FUNCTION_PREV_INSTR_SET.back().size())));
				for(byte b = 0; b < InstructionLength; b++)
					*(pInstructionPointer + b) ^= 0xAA;
				FUNCTION_PREV_INSTR_SET.back().push_back(InstructionPointer);
			}
			printf("\n");
		}
		if(FUNCTION_END_ADDRLIST.size() > 1 || FUNCTION_END_ADDRLIST.back() != InstructionPointer)
			CtxRecord->EFlags |= 0x100;

		return EXCEPTION_CONTINUE_EXECUTION;
		break;
	default:
		return EXCEPTION_CONTINUE_SEARCH;
		break;
	}
}

/*
	Initialize TLS with a callback to install the VEH 
	and deploy some anti-debug techniques.
*/
void WINAPI InitializeApplication(LPVOID hHandle, DWORD dwReason, LPVOID lpReserved)
{
	BOOL idp = IsDebuggerPresent();
	MASM
	{
		jmp short _DCPILTLoc
_DCPILTLocMkr:
		_emit 0xDE
		_emit 0xAD
		_emit 0xBE
		_emit 0xEF
_DCPILTLoc:
		push eax
		mov eax, dword ptr [_DCPILTLocMkr]
		mov dword ptr IltCollectionStartPtr, eax
		pop eax
	}

	AddVectoredExceptionHandler(VH_CALL_FIRST, DCPVEHFunctionEncapsulation);
}


