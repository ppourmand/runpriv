// Pasha Pourmand
// Friday May 20, 2016
// Hw 4

// Libraries
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

// pragmas
#pragma GCC diagnostic ignored "-Wwrite-strings";

// Macros
#define STUDENTUID 7005874
#define MIN_LIFE_OF_SNIFF 60

// namespace
using namespace std;

// debugging purposes
bool debug = false;

// function declarations
int check_student_uid(void);
int validate_user(void);
int check_for_sniff(void);
void change_sniff(void);

// Main
int main(void){
    // Variables for holding function statuses
    int student_uid_status = 0;
    int validate_user_status = 0;
    int check_for_sniff_status = 0;

    // checks for proper uid, exits if bad
    student_uid_status = check_student_uid();   
    if(student_uid_status == 1){    
        cerr << "Sorry, incorrect UID value. Exiting the program now." << endl;
        exit(1);
    }

    // checks CAS authentication, exits if bad
    validate_user_status = validate_user();
    if(validate_user_status == 1){
        cerr << "Sorry, invalid password was entered. Exiting program now." << endl;
        exit(1);
    }

    check_for_sniff_status = check_for_sniff();
    if(check_for_sniff_status == 1){
        exit(1);
    }

    // Change the ownership of sniff to root (UID 0), 
    // its group to proj (GID 95), and its protection mode to 4550
    change_sniff();

    return 0;
}

//=============================================================================
// Function for checking uid
// returns 0 for success
// returns 1 for failure
//=============================================================================
int check_student_uid(void){
    // debug purposes
    if(debug){
        cout << ">>> We are in check_student_uid() now" << endl;
    }

    int uid = 0;
    uid = getuid();

    // very basic, if uid of user and known student uid are different, return 1
    if(uid != STUDENTUID){
        return 1;
    }

    return 0;
}


//=============================================================================
// Ask user for pw
// validate against UC DAVIS CENTRAL AUTHENTICATION SYSTEM
// return 0 for success
// return 1 for failure
//=============================================================================
int validate_user(void){
    if(debug){
        cout << ">>> We are in validate_user() now" << endl;
    }

    // setting variables for execve
    char * envp[] = {
        "PATH=/bin:/usr/bin",
        "IFS=\t\n",
        "SHELL=/pkg/bin/tcsh",
        0
    };
    char * argv[] = {"/bin/kinit", 0};
    int pid = 0;
    int status = 0;

    // fork to create child process
    if ((pid = fork()) < 0){
        exit(1);
    }
    // this is the child process
    else if(pid == 0){
        status = execve(argv[0], &argv[0], envp);
    }
    // if we are in parent process, wait until child is done
    else{
        while(wait(&status) != pid);
    }

    // success of execve    
    if(status == 0){
        return 0;
    }

    // otherwise something went wrong, return 1
    return 1;
}

//=============================================================================
// Check to see if current directory contains file named sniff
// returns 0 for success
// returns 1 for failure
//=============================================================================
int check_for_sniff(void){
    // for debug purposes
    if(debug){
        cout << ">>> inside check_for_sniff() now" << endl;
    }
    
    struct stat fileInformation; 
    int status;
    time_t now;

    // gets current time
    time(&now);

    // calls stat on sniff file 
    status = stat("sniff", &fileInformation);

    // if stat just broke
    if(status == -1){
        exit(1);
    }
    
    // immediately exist if the sniff file doesn't exist
    if(errno == ENOENT && status == -1){
        cout << "Sorry, sniff does not exist. Exiting the program now." << endl;
        return 1;
    }   

    // Now that we know the file exists, however..

    // if time last modified is over 1 minute ago, return
    // macro used instead of magic number for robustness
    if(difftime(now, fileInformation.st_mtime) > MIN_LIFE_OF_SNIFF){
        cout << "Sorry, sniff was last modified over a minute ago. Exiting the program now." << endl;
        return 1;
    }  
    
    // owner is not same as student, return
    if(fileInformation.st_uid != STUDENTUID){
        cerr << "Sorry, owner is not same as student. Exiting the program now." << endl;
        return 1;
    }
    
    // if the owner does not have execute permissions, return
    if(!(fileInformation.st_mode & S_IXUSR)){
        cout << "Sorry, owner does not have execute permissions. Exiting the program now." << endl;
        return 1;
    }

    // if others have read, write, and execute  
    if(fileInformation.st_mode & S_IRWXO){
        cout << "Sorry, others (not in group) have read, write, execute permission. Exiting the program now." << endl;
        return 1;
    }   

    // if others have read permissions, exit
    if(fileInformation.st_mode & S_IROTH){
        cout << "Sorry, others have read permission. Exiting the program now." << endl;
        return 1;
    }

    // if others have write permissions, exit
    if(fileInformation.st_mode & S_IWOTH){
        cout << "Sorry, others have write permission. Exiting the program now." << endl;
        return 1;
    }

    // if others have execute permissions, exit
    if(fileInformation.st_mode & S_IXOTH){
        cout << "Sorry, others have execute permission. Exiting the program now." << endl;
        return 1;
    }

    // if group has read, write, and execute permission, exit
    if(fileInformation.st_mode & S_IRWXG){
        cout << "Sorry, group has read, write, and execute permission. Exiting the program now." << endl;
        return 1;
    }

    // if group has read permission, exit
    if(fileInformation.st_mode & S_IRGRP){
        cout << "Sorry, group has read permission. Exiting the program now." << endl;
        return 1;
    }

    // if group has write permission, exit
    if(fileInformation.st_mode & S_IWGRP){
        cout << "Sorry, group has write permission. Exiting the program now." << endl;
        return 1;
    }

    // if group has execute permission, exit
    if(fileInformation.st_mode & S_IXGRP){
        cout << "Sorr, group has execute permission. Exiting the program now." << endl;
        return 1;
    }
    

    return 0;
}

//=============================================================================
// Changes ownership/protection/group of sniff
//=============================================================================
void change_sniff(void){

    // set environment up for chown 
    char * envp[] = {
        "PATH=/bin:/usr/bin",
        "IFS=\t\n",
        "SHELL=/pkg/bin/tcsh",
        0
    };

    char * argv[] = {"usr/bin/chown", "root:proj sniff", 0};
    int pid = 0;
    int status = 0;
    int chmod_status = 0;

    // fork to create child process
    if ((pid = fork()) < 0){
        exit(1);
    }
    // this is the child process
    else if(pid == 0){
        status = execl("/usr/bin/chown", "","root:proj", "sniff",0);
    }
    // if we are in parent process, wait until child is done
    else{
        while(wait(&status) != pid);
    }

    // If chown fails, exit the program
    if(status == -1){ 
        exit(1);
    }

    // return value if invalid group/invalid user
    if(status == 256){
        exit(1);
    }

    // At this point, we have valid group/user so use chmod to change
    // protection mode value
    // check chmod return value for robustness!
    chmod_status = chmod("./sniff", 04550);
    
    if(chmod_status == -1){
        printf("There was an error with chmod. Errno value: %s", strerror(errno));
    }
}