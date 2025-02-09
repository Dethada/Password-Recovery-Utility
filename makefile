CC = cc
LIBS = -lcrypt -fopenmp

generator: generator_3177.c functions.o
	$(CC) -o generator generator_3177.c functions_3177.o $(LIBS)

recovery: recovery_3177.c functions.o
	$(CC) -o recovery recovery_3177.c functions_3177.o

functions.o: functions_3177.c functions_3177.h
	$(CC) -c functions_3177.c

all: generator recovery

clean:
	rm -f generator recovery functions_3177.o