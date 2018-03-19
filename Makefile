all: siphash

siphash: main.o
	gcc -o siphash main.o

main.o: main.cpp
	gcc -c -std=c++11 main.cpp

clean:
	rm -f siphash main.o *~
