all: siphash

siphash: main.o
	g++ -fopenmp -o siphash main.o -std=c++11

main.o: main.cpp
	gcc -std=c++11 -c -O2 -fopenmp main.cpp

clean:
	rm -f siphash main.o *~
