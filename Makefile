OBJECTS= ./build/libelf_parser.o
INCLUDE=-I./

all: ${OBJECTS}
	gcc -fPIC -shared ${INCLUDE} ${OBJECTS} -g -o libelf_parser.so

./build/libelf_parser.o:
	gcc ${INCLUDE} libelf_parser.c -o ./build/libelf_parser.o -c -g

test: test.c
	gcc test.c -g -no-pie -o test

clean:
	rm -f ./build/*.o
	rm -f libelf_parser.so
	rm -f test