# Put your jdk-include address on "-I" paths
#clang -g -Wl,-rpath,./ -O3 -o liboreblkc.so -march=native -lgmp -lssl -shared -I../../jdk/include/ -I../../jdk/include/linux/ -L./ -loreblk -lcrypto blkOreC.c -fPIC
clang -g -Wl,-rpath,./fastore -O3 -o fastore/liboreblkc.so -march=native -lgmp -lssl -shared -I../../jdk1.8.0_144/include/ -I../../jdk1.8.0_144/include/linux/ -L./fastore -loreblk -lcrypto blkOreC.c -fPIC
