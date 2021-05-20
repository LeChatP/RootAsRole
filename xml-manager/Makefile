## Makefile

CFLAGS 	= -W -Wall -Wextra
DEBUG 	= -ggdb -fno-omit-frame-pointer
LDLIBS	= -lcap -lxml2

SRC = $(wildcard ./*.c)
OBJ = $(SRC:./%.c=./%.o)

all: $(OBJ) addrole deleterole

addrole: addrole.o xml_manager.o
	$(CC) addrole.o xml_manager.o verifier.o xmlNode.o -o $@ $(LDLIBS)

deleterole: deleterole.o xml_manager.o
	$(CC) deleterole.o xml_manager.o verifier.o xmlNode.o -o $@ $(LDLIBS)

$(OBJ): ./%.o: ./%.c
	$(CC) -o $@ -c $(CFLAGS) $(DEBUG) $<

clean:
	$(RM) ./*.o

fclean: clean
	$(RM) addrole deleterole

re: fclean all

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

