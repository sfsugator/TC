/****************************************************************************************
Author: Alfred Muller
File Name: alfshell.c
Homework: #3
A program that mimics the shell in Posix using fork() and execvp().
A while loop is generated that prints a prompt that includes the name of the shell,
current date, and current time. The user can then enter commands as normal and the
commands are parsed . a fork is called and the parsed commands are executed. The program
waits for the processes to finish.
***************************************************************************************/



#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define ARGUMENTS   5

int loop();//loop to enter commands
char *readLine(void);//read in the input
int parseLine(char *command, char **args);//parse the input
int executeLine(char **args, int length);//pass the parsed input for forking and execution

int main() {
    
    
    loop();
    
    return 0;
}

int loop(){
    char *buff, buffer[64];//buff will hold input line, buffer is for prompt
    char *args[ARGUMENTS];//the arguments after parsing go here
    char exit[] ={'e','x','i', 't'}, cd[] = {'c', 'd'};//checks for exit and cd
    int  len=0;
    
    
    while(1){
        
        
        time_t current = time(NULL); /* Gets GMT time as a time_t. */
        struct tm* pLocal = localtime(&current); /* Converts to local time in broken down format. */
        strftime(buffer, sizeof(buffer), "<*AlfShell-[%X]-%B %d %Y*>", pLocal); /* Formats as string into provided buffer. */
        printf("%s", buffer);
        //read the input commands
		buff = readLine();
        //if the input command is "exit", then do so
        if(strncmp(exit, buff, 4) == 0) {
            printf("Exiting Alf Shell. Goodbye!\n");
            return 0;
        }
		//we must clear the arguments after a command is passed or they persist
        for(int i =0; i <ARGUMENTS;i++){
            args[i] = NULL;
        }
        
        //
        len = parseLine(buff, args);
		//check for "cd" builtin command, builtins must be handled manually
        if(strncmp(cd, buff, 2) == 0) {

            chdir(args[1]);
        }

		//input was not exit or cd, so send input to execute function
        else
        executeLine(args, len);
        
        
    }
    
    
    return 0;
}

//readLine uses getLine with a buffer of 1024 to get the input and returns the line
char *readLine(void)
{
    char *line = NULL;
    size_t bufsize = BUFFER_SIZE;
    getline(&line, &bufsize, stdin);
    return line;
}
/*parseLine uses tokens and delimiter (white space, newline) to break down 
input line into arguments to put into args array*/
int parseLine(char *command, char **args){
    
    int position = 0;
    char *readCommand = NULL;
    char delims[] = {" \n"};
    
    readCommand = strtok(command, delims);//tokenize input line
    while(readCommand != '\0'){
        
        args[position] = strdup(readCommand);
        readCommand = strtok(NULL, delims);
        position++;
    }
    //returns the number of arguments in args array
    return position;
}

/*executeLine is where we finally fork and execvp the arguments passed. 
we create a chid process and wait for it to finish*/
int executeLine(char **args, int length){
    pid_t pID;
    int childProcessStatus;
    
    
    switch(pID = fork()){//fork and execvp
        case 0:
            execvp(args[0], args);
            printf("Error in argument \"%s\": %s\n", args[0], strerror(errno));
            return 0;
        case -1:
            printf("Error in Child: %s\n", strerror(errno));
            return -1;
        default:
            waitpid(pID, &childProcessStatus, 0); // wait for child process to finish
            return 0;
    }
}
