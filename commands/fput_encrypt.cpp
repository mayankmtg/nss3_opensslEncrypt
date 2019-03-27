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
#include <utility> 
#include <pthread.h>
#include <sys/xattr.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <shadow.h>
#include <openssl/evp.h>
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
string getProcessPasswordHash(string username){
	struct spwd* shadowpwd = getspnam(username.c_str());
	if(shadowpwd == (struct spwd*) 0 ){
		cout << "Error: In getting password from shadows file"<< endl;
		exit(0);
	}
	string retString = shadowpwd->sp_pwdp;
	int pos = retString.find('$');
	for (int i=0;i<2;i++){
		pos = retString.find('$', pos+1);
	}
	retString = retString.substr(pos+1);
	return retString;
}

pair<string, string> getKeyIVfromPassword(const char* password){
	const EVP_CIPHER *cipher;
	const EVP_MD *dgst = NULL;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	// const char *password = password.c_str();
	const unsigned char *salt = NULL;
	int i;

	OpenSSL_add_all_algorithms();

	cipher = EVP_get_cipherbyname("aes-256-cbc");
	if(!cipher) {
		cout << "Error: no such cipher" << endl;
		exit(0);
	}

	dgst=EVP_get_digestbyname("md5");
	if(!dgst) {
		cout << "Error: no such digest" << endl;
		exit(0);
	}

	if(!EVP_BytesToKey(cipher, dgst, salt,(unsigned char *) password,strlen(password), 1, key, iv)){
		cout << "Error: EVP_BytesToKey failed" << endl;
		exit(0);
	}

	string key_string = "";
	for(i=0; i<cipher->key_len; ++i){
		char buff[4];
		sprintf(buff, "%02x", key[i]);
		key_string += string(buff);
	}

	string iv_string = "";
	for(i=0; i<cipher->iv_len; ++i){
		char buff[4];
		sprintf(buff, "%02x", iv[i]);
		iv_string += string(buff);
	}

	pair<string, string> retPair;
	retPair.first = key_string;
	retPair.second = iv_string;
	return retPair;
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

bool fileExists(string pathname){
	std::ifstream infile(pathname.c_str());
    return infile.good();
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

void crypto_error(int a){
	cout << "Error: Handling Errors"<< endl;
	cout << a << endl;
	exit(0);
}
/*
wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())){
		crypto_error(1);
	}
	if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1){
		crypto_error(1);
	}
	if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1){
		crypto_error(1);
	}
	ciphertext_len = len;
	if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1){
		crypto_error(1);	
	} 
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

/*
wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		crypto_error(1);
	}
	if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1){
		crypto_error(2);
	}

	if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1){
		crypto_error(3);
	}
	plaintext_len = len;

	if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1){
		crypto_error(4);
	} 
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

string getFileContents(string filename, string key_string, string iv_string){
	ifstream infile;
	infile.open(filename.c_str());
	string content( (std::istreambuf_iterator<char>(infile) ),(std::istreambuf_iterator<char>()));
	unsigned char buff[500];
	int decryp_len = decrypt((unsigned char *)content.c_str(), content.length(), (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(), buff);
	string decrypT = string((const char *) buff, (const char *) buff + decryp_len);
	decrypT = decrypT.substr(0,decryp_len);
	return decrypT;
	// string userLine;
	// string returnString="";
	// while(getline(infile, userLine)){
	// 	unsigned char buff[500];
	// 	int decryp_len = decrypt((unsigned char *)userLine.c_str(), userLine.length(), (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(), buff);
	// 	string decrypT = string((const char *) buff);
	// 	decrypT = decrypT.substr(0,decryp_len);
	// 	returnString+=decrypT + "\n";
	// }
	// infile.close();
	// return returnString.substr(0,returnString.length()-1);
}

string getArgumentOwner(string filename){
	return getAttribute(filename, "user.owner",2);
}

bool setAttribute(string path, string name, string value){
	// size is the size of the return expected since
	// getxattr gives garbage after the intended size
    int retval = setxattr(path.c_str(), name.c_str(), value.c_str(), (size_t)value.length(), 0);
    if(retval != 0){
        cout << "Error: Setting Attributes"<< endl;
        return false;
    }
    return true;
}

void appendToFile(string filename, string content, string key_string, string iv_string){
	ofstream outfile;
	unsigned char buff[500];
	content = getFileContents(filename, key_string, iv_string) + content;
	int cipherT_len = encrypt((unsigned char *)content.c_str(), content.length(), (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(),buff);
	buff[cipherT_len] = '\0';
	string cipherT = string((const char* )buff,(const char *) buff+cipherT_len);

	// unsigned char buff2[500];
	// int decryp_len = decrypt((unsigned char *)cipherT.c_str(), cipherT_len, (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(),buff2);
	// cout << decryp_len<< endl;
	// string decrypT = string((const char* )buff2);
	// decrypT = decrypT.substr(0,decryp_len);
	// cout << decrypT << endl;
	// cout << "Encryption Successful" << endl;

	outfile.open(filename.c_str());
	outfile << cipherT;
	outfile.close();
}

void writeToFile(string filename, string content, string key_string, string iv_string){
	ofstream outfile;
	unsigned char buff[500];
	int cipherT_len = encrypt((unsigned char *)content.c_str(), content.length(), (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(),buff);
	buff[cipherT_len] = '\0';
	string cipherT = string((const char* )buff,(const char *) buff+cipherT_len);

	// unsigned char buff2[500];
	// int decryp_len = decrypt((unsigned char *)cipherT.c_str(), cipherT_len, (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(),buff2);
	// cout << decryp_len<< endl;
	// string decrypT = string((const char* )buff2);
	// decrypT = decrypT.substr(0,decryp_len);
	// cout << decrypT << endl;
	// cout << "Encryption Successful" << endl;

	outfile.open(filename.c_str());
	outfile << cipherT;
	outfile.close();
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
	uid_t currUid = getProcessRuid();
	string currUser = getProcessUsername(currUid);
	string currGroup = getProcessGroupname(currUid);
	string currDirec = getProcessDirectory();
	string currPasswordHash = getProcessPasswordHash(currUser);
    //

	pair<string,string> currKeyIv = getKeyIVfromPassword(currPasswordHash.c_str());
	// cout << currKeyIv.first<< endl;
	// cout << currKeyIv.second<< endl;

	string pathDirec = getPathDirectory(currDirec, argument);
    if(pathDirec.length() < rootDir.length()){
        cout << "Error: Unauthorised Access" << endl;
        exit(0);
    }

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
			string argumentOwner = getArgumentOwner(argument);
			string argumentPasswordHash = getProcessPasswordHash(argumentOwner);
			pair<string,string> ownerKeyIv = getKeyIVfromPassword(argumentPasswordHash.c_str());
            appendToFile(argument, fileInput, ownerKeyIv.first, ownerKeyIv.second);
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
        writeToFile(argument, fileInput, currKeyIv.first, currKeyIv.second);
		generateSignatureSequence(pathName);
    }
    else{
        cout << "Error: No write permissions for the directory" << endl;
    }

	return 0;
}