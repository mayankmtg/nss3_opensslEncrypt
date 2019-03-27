#!/bin/sh

make

chown fr fput_encrypt
chgrp root fput_encrypt
mv fput_encrypt /usr/bin/
chmod u+s /usr/bin/fput_encrypt

chown fr fget_encrypt
chgrp root fget_encrypt
mv fget_encrypt /usr/bin/
chmod u+s /usr/bin/fget_encrypt

chown fr fsign
chgrp root fsign
mv fsign /usr/bin/
chmod u+s /usr/bin/fsign

chown fr fverify
chgrp root fverify
mv fverify /usr/bin/
chmod u+s /usr/bin/fverify

chown fr fput
chgrp root fput
mv fput /usr/bin/
chmod u+s /usr/bin/fput

chown fr fget
chgrp root fget
mv fget /usr/bin/
chmod u+s /usr/bin/fget