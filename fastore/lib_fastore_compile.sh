clang -g -Wall -O3 -o libcrypto.so -march=native -lgmp -lssl -lcrypto -shared -L/usr/lib/x86_64-linux-gnu/ crypto.c -fPIC
clang -g -Wall -O3 -o liboreblk.so -march=native -lgmp -lssl -lcrypto -shared -L./ ore_blk.c -fPIC
