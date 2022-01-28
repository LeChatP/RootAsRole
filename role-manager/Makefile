###	@Author : Anderson Hemlee
## 	Makefile for role_manager

# Compiler
CC	:=	gcc

# Options
FLAGS 	:= -W -Wall -Wextra -lcap `xml2-config --libs`
DEBUG	:= TRUE

# Debug / Optimization
ifeq	($(DEBUG),TRUE)
	OPTIONS += -ggdb -g3 -fno-omit-frame-pointer
else
	OPTIONS += -Ofast
endif

SRC = $(wildcard ./*.c)
OBJ = $(SRC:%.c=%.o)

all: $(OBJ) addrole editrole deleterole

addrole: addrole.o
	$(CC) addrole.o help.o list_manager.o verifier.o xmlNode.o -o $@ $(FLAGS) $(OPTIONS)

editrole: editrole.o
	$(CC) editrole.o help.o verifier.o xmlNode.o -o $@ $(FLAGS) $(OPTIONS)

deleterole: deleterole.o
	$(CC) deleterole.o help.o verifier.o xmlNode.o -o $@ $(FLAGS) $(OPTIONS)

$(OBJ): %.o: %.c
	$(CC) -o $@ -c $< `xml2-config --cflags`

clean:
	$(RM) ./*.o

fclean: clean
	$(RM) addrole editrole deleterole

re: fclean all

install:
	cp addrole editrole deleterole /usr/bin/

uninstall:
	rm -f /usr/bin/addrole /usr/bin/editrole /usr/bin/deleterole
