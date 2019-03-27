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
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>


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

string getOwnerPasswordHash(string username){
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

string getAttribute(string path, string name, int size){
	// size is the size of the return expected since
	// getxattr gives garbage after the intended size
	char buff[size+1];
	ssize_t retSize = getxattr(path.c_str(), name.c_str(), buff, size);
	if (retSize < 0) {
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

bool fileReadAllowed(string currUser, uid_t currUserId, string path){
	string userP = getUserPermissions(currUser, path);
	string groupP = getGroupUnionPermissions(currUser, currUserId, path);
	if(userP != ""){
		if(userP[0]=='r'){
			return true;
		}
		else{
			return false;
		}
	}
	if(groupP[0]=='r'){
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


string getFileContentsDecrypt(string filename, string key_string, string iv_string){
	ifstream infile;
	infile.open(filename.c_str());
	string content( (std::istreambuf_iterator<char>(infile) ),(std::istreambuf_iterator<char>()));
	unsigned char buff[500];
	int decryp_len = decrypt((unsigned char *)content.c_str(), content.size(), (unsigned char *)key_string.c_str(), (unsigned char *)iv_string.c_str(), buff);
	string decrypT = string((const char *) buff,(const char *) buff+decryp_len);
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

string getFileContents(string filename){
	ifstream infile;
	infile.open(filename.c_str());
	string content( (std::istreambuf_iterator<char>(infile) ),(std::istreambuf_iterator<char>()));
	return content;
	// string userLine;
	// string returnString="";
	// while(getline(infile, userLine)){
	// 	returnString+=userLine;
	// }
	// infile.close();
	// return returnString;
}

string getArgumentOwner(string filename){
	return getAttribute(filename, "user.owner",2);
}


string generateSHA256Hash(string str){
    unsigned char hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    char m[64];
    for(int i = 0; i < 32; i++){
        // sprintf(m,"%02x",(int)hash[i]);
        ss << hex;
        ss << setw(2) << setfill('0');
        ss << (int)hash[i];
    }
    return ss.str();
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

int main(int argc, char ** argv){
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
	

    argument = getCorrectedPath(currDirec, argument);
    if(argument.length() < rootDir.length()){
		cout << "Error: Unauthorised Access" << endl;
		exit(0);
	}
	else if(argument.substr(0,rootDir.length()) != rootDir ){
		cout << "Error: Unauthorised Access" << endl;
		exit(0);
	}
	else {
		string argumentOwner = getArgumentOwner(argument);
		string argumentPasswordHash = getOwnerPasswordHash(argumentOwner);
		pair<string,string> currKeyIv = getKeyIVfromPassword(argumentPasswordHash.c_str());
		if(fileReadAllowed(currUser, currUid, argument)){
			string file_hash = generateSHA256Hash(getFileContents(argument));
            // cout << file_hash << endl;
			string signature = argument+".sign";
            string file_hmac = getFileContentsDecrypt(signature, currKeyIv.first, currKeyIv.second);
            // cout << file_hmac << endl;
            if(file_hash==file_hmac){
                cout << "Verification Successful" << endl;
            	cout << getFileContentsDecrypt(argument, currKeyIv.first, currKeyIv.second) << endl;
            }
            else{
                cout << "Verification Failed" << endl;
            }
		}
		else{
			cout << "Error: No permissions to read this directory" << endl;
			exit(0);
		}
	}

    return 0;
}
