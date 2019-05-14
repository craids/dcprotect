#include "dcplib.h"

void test1()
{
	DCPFunctionProlog
		printf("%s\n", "Inside PROTF1 (test)");
	DCPFunctionEpilog
	printf("%s\n", "Outside PROTF1 (test)");
	return;
}

void test2()
{
	DCPFunctionProlog
		printf("%s\n", "Inside PROTF2 (test)");
	DCPFunctionEpilog
		printf("%s\n", "Outside PROTF2 (test)");
	return;
}

int main()
{
	//DCPFunctionProlog
	printf("%s\n", "Entered Main");
	test1();
	test2();
	//DCPFunctionEpilog
	printf("%s\n", "Exiting Main");
	system("PAUSE");

	return 0; // Markers must NEVER encapsulate return statement.
}




