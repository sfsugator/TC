/*********************************************************************************************************
 Author: Alf Muller
 Source: hw7shellAlfWin.c
 Purpose: Extend your shell/command‐line interpreter from homework 3. The new functionality will include executing commands in the background using the & symbol; redirecting the standard input, standard output and standard error streams to or from files using the <, > and 2> symbols; redirecting and appending the standard output and standard error streams to files using the >> and 2>> symbols; and piping the standard output of one process to the standard input of another using the | symbol. This is the win32 version.
 
 *********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <time.h>

#define BUFFER_SIZE 4096

int main (){
	//shell start up
    printf("Starting Alf Shell. Type \"exit\" to close shell. \n");
	while(1){
		

		
		char buf[BUFFER_SIZE];
		char bufcopy[BUFFER_SIZE];
		char input[BUFFER_SIZE + 7];
		char input2[BUFFER_SIZE + 7];
		int size, i;
		int backgroundFlag = 0, pipeFlag = 0;
        SYSTEMTIME lt;//used for time string
        
        //attributes for various handles and functions
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		STARTUPINFO si2;
		PROCESS_INFORMATION pi2;
		HANDLE rhandle;
		HANDLE whandle;
		SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);
		ZeroMemory(&si2, sizeof(si2));
		ZeroMemory(&pi2, sizeof (pi2));
		si2.cb = sizeof(si2);
        
		//handle reset
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.dwFlags = STARTF_USESTDHANDLES;

        //custom shell prompt
        GetLocalTime(&lt);//get local time used in prompt below
        printf("<Alf Shell [%02d/%02d/%02d] %02d:%02d:%02d>", lt.wMonth, lt.wDay, lt.wYear, lt.wHour, lt.wMinute, lt.wSecond);
        
		//get user input, make a copy
		fgets(buf, BUFFER_SIZE, stdin);
		strncpy(bufcopy, buf, BUFFER_SIZE);

		//tokenize the buffer
		char delim[2] = " \n";//delimeter for strtok
		char *token;
		token = strtok(buf, delim);

		
		if(token != NULL){
			//exit string check,
			if(strcmp(token, "exit") == 0){
                printf("Exiting Alf Shell. Goodbye!\n");//acknowledhe the exit
				exit(0);
			}

			
			
			//add prefix (cmd /c) just like in previous homework
			strcpy(input, "cmd.exe /c ");
			while(token != NULL){
				if(strcmp(token, "&") == 0){//background check
					backgroundFlag = 1;
				}else if(strcmp(token, ">") == 0 || strcmp(token, "2>") == 0){//check for single rightarrows
					if(strcmp(token, ">") == 0){
						token = strtok(NULL, delim);
						if((si.hStdOutput = CreateFile(token, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS,
							FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE){//create file
							fprintf(stderr, "Error in creating output file\n");//error
							exit(0);
						}
					}else{//create file, no arrows
						token = strtok(NULL, delim);
						if((si.hStdError = CreateFile(token, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS,
							FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE){
							fprintf(stderr, "Error in creating output file\n");
							exit(0);
						}
					}//check for double right arrows
				}else if(strcmp(token, ">>") == 0 || strcmp(token, "2>>") == 0){
					if(strcmp(token, ">>") == 0){
						token = strtok(NULL, delim);
						//create file in append mode
						if((si.hStdOutput = CreateFile(token, FILE_APPEND_DATA, 0, &sa, OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE){
							if((si.hStdOutput = CreateFile(token, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS,
								FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE){
								fprintf(stderr, "Error in creating output file\n");//error
								exit(0);
							}
						}
					}else{
						token = strtok(NULL, delim);
						//create file in append mode, no arrows
						if((si.hStdError = CreateFile(token, FILE_APPEND_DATA, 0, &sa, OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE){
							si.hStdError = CreateFile(token, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS,
								FILE_ATTRIBUTE_NORMAL, NULL);
						}

						if(si.hStdError == INVALID_HANDLE_VALUE){
							fprintf(stderr, "Error in creating output file\n");
							exit(0);
						}
					}//left arrows
				}else if(strcmp(token, "<") == 0){
					token = strtok(NULL, delim);
					//open file for input
					if((si.hStdInput = CreateFile(token, GENERIC_READ, 0, &sa, OPEN_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE){
						fprintf(stderr, "Error in opening input file\n");
						exit(0);
					}//pipe called
				}else if(strcmp(token, "|") == 0){
					pipeFlag = 1;//pipe flag
					//right side of pipe
					strcpy(input2, "cmd /c ");
					token = strtok(NULL, delim);
					while(token != NULL){
						strcat(input2, token);
						strcat(input2, " ");
						token = strtok(NULL, delim);
					}
					//add null to end of buffer
					size = strlen(input2);
					input2[size - 1] = '\0';

				}else{
					strcat(input, token);
					strcat(input, " ");
				}
				token = strtok(NULL, delim);
			}
			
			//add \0 at end
			size = strlen(input);
			input[size - 1] = '\0';
			
			//second process for right side of pipe
			if(pipeFlag){
				
				if (!CreatePipe(&rhandle, &whandle, &sa, 0)){
					fprintf(stderr, "Create Pipe Failed\n");//error check CreatePipe
					exit(0);
				}
				si.hStdInput = rhandle;
				// left child
				if(!CreateProcess(NULL, input2, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)){
					fprintf(stderr, "CreateProcess failed.\n");
					return -1;
				}
				// right child
				si2.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
				si2.hStdError = GetStdHandle(STD_ERROR_HANDLE);
				si2.hStdOutput = whandle;
				si2.dwFlags = STARTF_USESTDHANDLES;
				if(!CreateProcess(NULL, input, NULL, NULL, TRUE, 0, NULL, NULL, &si2, &pi2)){
					fprintf(stderr, "CreateProcess2 failed.\n");
					return -1;
				}
			}else{
				// Start the child process. 
				if(!CreateProcess(NULL, input, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)){
					fprintf(stderr, "CreateProcess failed.\n");
					return -1;
				}
			}

			
			//wait for process
			if(pipeFlag){
				WaitForSingleObject(pi2.hProcess, INFINITE);
				WaitForSingleObject(pi.hProcess, INFINITE);
			}else{
				if(!backgroundFlag){
					WaitForSingleObject(pi.hProcess, INFINITE);
				}
			}
			
			

			// Close everything
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			if(si.hStdInput != GetStdHandle(STD_INPUT_HANDLE))CloseHandle(si.hStdInput);
			if(si.hStdError != GetStdHandle(STD_ERROR_HANDLE))CloseHandle(si.hStdError);
			if(si.hStdOutput != GetStdHandle(STD_OUTPUT_HANDLE))CloseHandle(si.hStdOutput);
			if(pipeFlag){
				CloseHandle(pi2.hProcess);
				CloseHandle(pi2.hThread);
				CloseHandle(rhandle);
				CloseHandle(whandle);
			}
		}
	}
	return 0;
}