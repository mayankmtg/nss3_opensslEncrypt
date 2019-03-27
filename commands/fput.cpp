#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <iostream>
#include <list>
#include <fstream>
#include <dirent.h>
#include <strings.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <algorithm>
#include <pthread.h>
#include <sys/xattr.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <sys/wait.h>

using namespace std;

static string rootDir = "/home/mayank/simple_slash";
uid_t getProcessRuid(){
	uid_t ruid;
    uid_t euid;
    uid_t suid;
    int retVal = getresuid(&ruid, &euid, &suid);
    if(retVal!=0){
		cout << "Error: In getting ruid"<< endl;
		exit(0);
	}
	return ruid;
}

string getProcessUsername(uid_t ruid){
	struct passwd * pwuid = getpwuid(ruid);
    string username = "";
    if(pwuid){
        username = string(pwuid->pw_name);
    }
	else{
		cout << "Error: In getting username"<< endl;
		exit(0);
	}
	return username;
}
string getProcessGroupname(uid_t ruid){
	struct passwd * pwuid = getpwuid(ruid);
    string groupname = "";
    if(pwuid){
		struct group * grpstruct= getgrgid(pwuid->pw_gid);
		if(grpstruct!=NULL){
			groupname = grpstruct->gr_name;
		}
		else{
			cout << "Error: In getting groupname"<< endl;
		}
		return groupname;
    }
	else{
		cout << "Error: In getting groupname"<< endl;
		exit(0);
	}
	return groupname;
}
string getProcessDirectory(){
	char pwd[200];
	char* check = getcwd(pwd, 200);
	if(check == NULL){
		cout << "Error: In getting present working directory"<< endl;
		exit(0);
	}
	string retString = pwd;
	return retString;
}


// returns the directory that the file is contained in
string getPathDirectory(string currDirec, string path){
    if(path[0]=='/'){
		path = rootDir + path;
	}
	else{
		path = currDirec +"/"+ path;
	}
    string filename_copy(path);
	reverse(filename_copy.begin(), filename_copy.end());
	int pos = filename_copy.find('/');
	string sub = filename_copy.substr(pos+1);
	reverse(sub.begin(), sub.end());
    char buf[300];
	char *res = realpath(sub.c_str(), buf);
	if(res){
		string returnPath = buf;
		return returnPath;
	}
	else{
		cout << "Error: Incorrect path to file"<< endl;
		exit(0);
	}
}

// returns the filename for the path entered
string getPathName(string currDirec, string path){
    if(path[0]!='/'){
		path = currDirec+ "/" + path;
	}
	string filename_copy(path);
	reverse(filename_copy.begin(), filename_copy.end());
	int pos = filename_copy.find('/');
	string sub = filename_copy.substr(0,pos);
	reverse(sub.begin(), sub.end());
	return sub;
}

void appendToFile(string filename, string content){
	ofstream outfile;
	// cout << content << endl;
	// cout << filename<< endl;
	outfile.open(filename.c_str(), ios::app);
	outfile << content;
	outfile.close();
}

// returns the corrected paths
string getCorrectedPath(string currDirec, string path){
	if(path[0]=='/'){
		path = rootDir + path; // absolute path
	}
	else{
		path = currDirec + "/" + path; // relative path
	}
	char buf[300];
	// cout << path << endl;
	char *res = realpath(path.c_str(), buf);
	if(res){
		string returnPath = buf;
		return returnPath;
	}
	else{
		cout << "Error: In path resolution"<< endl;
		exit(0);
	}
}

string getAttribute(string path, string name, int size){
	// size is the size of the return expected since
	// getxattr gives garbage after the intended size
	char buff[size+1];
	ssize_t retSize = getxattr(path.c_str(), name.c_str(), buff, size);
	if (retSize < 0) {
	       // cout << "Not found attribute "<< name << endl;
		return "";
	}
	buff[size]='\0';
	string temp = buff;
	return temp;
}

string getUserPermissions(string username, string path){
	string name = "user.user." + username;
	return getAttribute(path, name, 3);
}
string getGroupPermissions(string groupname, string path){
	string name = "user.group."+groupname;
	return getAttribute(path, name, 3);
}
string getGroupUnionPermissions(string currUser, uid_t currUserId, string path){
	struct passwd * pwuid = getpwuid(currUserId);
	gid_t userGroups[10];
    int nog=10;
    int retVal = getgrouplist(currUser.c_str(),pwuid->pw_gid,userGroups,&nog);
    if(retVal<0){
        cout << "Error: In getting groups" << endl;
        return "";
    }
	string finalPermissions = "---";
    for (int i=0;i<nog;i++){
		struct group * grpstruct= getgrgid(userGroups[i]);
		string groupP = getGroupPermissions(grpstruct->gr_name, path);
		if(groupP == ""){
			continue;
		}
		if(groupP[0]=='r'){
			finalPermissions[0]='r';

		}
		if(groupP[1]=='w'){
			finalPermissions[1]='w';
		}
		if(groupP[2]=='x'){
			finalPermissions[2]='x';
		}
    }
	return finalPermissions;
}

bool fileExists(string pathname){
	std::ifstream infile(pathname.c_str());
    return infile.good();
}

bool fileWriteAllowed(string currUser, uid_t currUserId, string path){
    string userP = getUserPermissions(currUser,path);
    string groupP = getGroupUnionPermissions(currUser,currUserId, path);
    if(userP!=""){
        if(userP[1]=='w'){
            return true;
        }
        else{
            return false;
        }
    }
    if(groupP[1]=='w'){
        return true;
    }
    return false;
}

bool setAttribute(string path, string name, string value){
	// size is the size of the return expected since
	// getxattr gives garbage after the intended size
    int retval = setxattr(path.c_str(), name.c_str(), value.c_str(), (size_t)value.size(), 0);
    if(retval != 0){
        cout << "Error: Setting Attributes"<< endl;
        return false;
    }
    return true;
}

void generateSignatureSequence(string pathName){
	pid_t parent = getpid();
	pid_t pid = fork();

	if(pid == -1){
		cout << "Error: Forking and Execing"<< endl;
	}
	else if(pid > 0){
		int status;
		waitpid(pid, &status, 0);
		exit(0);
	}
	else{
		// we are the child
		char *my_envp[] = {NULL};
		char *my_args[] = {"/usr/bin/fsign",(char*)(pathName.c_str()), NULL};
		my_args[1]=(char *)pathName.c_str();
		execve(my_args[0],my_args, my_envp);
		_exit(EXIT_FAILURE);
	}
}

int main(int argc, char** argv){
    if(argc!=2){
		cout << "Error: Incorrect number of arguments" << endl;
		exit(0);
	}
    string argument = argv[1];
    
    // Process Variables
	string currDirec = getProcessDirectory();
	uid_t currUid = getProcessRuid();
	string currUser = getProcessUsername(currUid);
	string currGroup = getProcessGroupname(currUid);
    // 
    
    string pathDirec = getPathDirectory(currDirec, argument);
    if(pathDirec.length() < rootDir.length()){
        cout << "Error: Unauthorised Access" << endl;
        exit(0);
    }
    // handled if path to file is invalid

    string pathName = getPathName(currDirec, argument);
    argument = pathDirec + "/" + pathName;
    if(argument.length() < rootDir.length()){
		cout << "Error: Unauthorised Access" << endl;
		exit(0);
	}
	else if(argument.substr(0,rootDir.length()) != rootDir ){
		cout << "Error: Unauthorised Access" << endl;
		exit(0);
	}
    else if(fileExists(argument)){
        if(fileWriteAllowed(currUser, currUid, argument)){
            string fileInput = "";
            string line;
            cout << "Type Q to quit the prompt."<< endl;
            while(getline(cin, line)){
                if(line == "Q"){
                    break;
                }
                fileInput += line + "\n";
            }
            appendToFile(argument, fileInput);
			generateSignatureSequence(pathName);
        }
        else{
            cout << "Error: Cannot write to file"<< endl;
        }
    }
    else if(fileWriteAllowed(currUser, currUid, pathDirec)){
        ofstream file(argument.c_str());
        bool t1 = setAttribute(argument, string("user.owner"),currUser);
        bool t2 = setAttribute(argument, string("user.group"),currGroup);
        // TODO: replace this group from currGroup to the group of directory
        bool t3 = setAttribute(argument, string("user.user."+currUser),string("rwx"));
        bool t4 = setAttribute(argument, string("user.group."+currGroup),string("r--"));
        // TODO: replace this group from currGroup to the group of directory
        bool fileFinish = t1 && t2 && t3 && t4;
        if(!fileFinish){
            remove(argument.c_str());
        }
        string fileInput = "";
        string line;
        cout << "Type Q to quit the prompt...."<< endl;
        while(getline(cin, line)){
            if(line == "Q"){
                break;
            }
            fileInput += line + "\n";
        }
        appendToFile(argument, fileInput);
		generateSignatureSequence(pathName);
    }
    else{
        cout << "Error: No write permissions for the directory" << endl;
    }
    return 0;
}
