.PHONY: all clean

all:
	clang -O2 -Wall -Wextra -pedantic -o visualizer fd_table_visualizer.c

clean:
	rm visualizer
