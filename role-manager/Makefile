## Makefile

CFLAGS 	= -W -Wall -Wextra
DEBUG 	= -ggdb -fno-omit-frame-pointer
LDLIBS	= -lcap -lxml2

SRC = $(wildcard ./*.c)
OBJ = $(SRC:./%.c=./%.o)

all: $(OBJ) addrole editrole deleterole

addrole: addrole.o
	$(CC) addrole.o help.o verifier.o xmlNode.o -o $@ $(LDLIBS)

editrole: editrole.o
	$(CC) editrole.o help.o verifier.o xmlNode.o -o $@ $(LDLIBS)

deleterole: deleterole.o
	$(CC) deleterole.o help.o verifier.o xmlNode.o -o $@ $(LDLIBS)

$(OBJ): ./%.o: ./%.c
	$(CC) -o $@ -c $(CFLAGS) $(DEBUG) $<

clean:
	$(RM) ./*.o

fclean: clean
	$(RM) addrole editrole deleterole

re: fclean all

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"
