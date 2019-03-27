all: fputencmake fgetencmake fsignmake fverifymake fputmake fgetmake
fputencmake: fput_encrypt.cpp
			g++ fput_encrypt.cpp -o fput_encrypt -lcrypto -g
fgetencmake: fget_encrypt.cpp
			g++ fget_encrypt.cpp -o fget_encrypt -lcrypto -g
fsignmake: fsign.cpp
			g++ fsign.cpp -o fsign -lcrypto -g
fverifymake: fverify.cpp
			g++ fverify.cpp -o fverify -lcrypto -g
fputmake: fput.cpp
			g++ fput.cpp -o fput
fgetmake: fget.cpp
			g++ fget.cpp -o fget -lcrypto -g