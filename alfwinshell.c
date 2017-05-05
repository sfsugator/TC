/****************************************************************************************
Author: Alfred Muller
File Name: alfwinshell.c
Homework: #3
A program that mimics the command line interpreter for Windows using CreateProcess.
A while loop is generated that prints a prompt that includes the name of the shell,
current date, and current time. The user can then enter commands as normal and the
commands are prepended with "cmd.exe /c" and passed to CreateProcess. A new process
is then executed and the system waits for the process to finish before closing appropriate
handles.
***************************************************************************************/




#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <tchar.h>

#define BUF_SIZE 1024


int executeLine(char *commandLine);//CreateProcess function lives here
int loop();//A loop to enter commands

int main() {

	loop();

	return 0;

}
int loop() {
	char line[BUF_SIZE];//holds the entered command
	char command[BUF_SIZE];//holds line prepended with 'cmd.exe /c'
	char exit[] = { 'e', 'x', 'i', 't' };//used to compare with line for exiting
	int result = 0;
	SYSTEMTIME lt;//used for time string

	printf("Starting Alf Shell. Type \"exit\" to close shell. \n");
	while (1) {//loop to enter commands until exit is typed

		GetLocalTime(&lt);//get local time used in prompt below
		printf("<Alf Shell [%02d/%02d/%02d] %02d:%02d:%02d>", lt.wMonth, lt.wDay, lt.wYear, lt.wHour, lt.wMinute, lt.wSecond);


		//get the input line from terminal, buffer size 1024
		if (fgets(line, sizeof(line), stdin) == NULL) { break; }
		//compare to "exit", if true, close shell
		if (strncmp(exit, line, 4) == 0) {
			printf("Exiting Alf Shell. Goodbye!\n");
			return 0;
		}
		/*prepend the string to the command entered, a hint in the directions
		  for the homework would have been great here, took me a week to find this*/
		strcpy(command, "cmd.exe /c ");
		strcat(command, line);

		//send the new string to executeLine()
		result = executeLine(command);


	}
	return 0;
}

/* executeLine is where CreateProcess lives, takes the prepended input string
and uses it as the second argument*/
int executeLine(char *commandLine) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	//mem flush
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	//create the new process
	if (!CreateProcess(NULL,
		&commandLine[0],
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi)) {
		printf("Createprocess failed (%d).\n", GetLastError());
		return -1;
	}
	//wait for process to finish
	WaitForSingleObject(pi.hProcess, INFINITE);

	//close handles and error check
	if (!CloseHandle(pi.hProcess)) {
		printf("Error closing hProcess\n");
		return -1;
	}
	else if (!CloseHandle(pi.hThread)) {
		printf("Error closing hThread\n");
		return -1;
	}
	else

		return 0;

}

