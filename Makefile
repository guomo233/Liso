SRC_DIR := src
OBJ_DIR := obj
# all src files
SRC := $(wildcard $(SRC_DIR)/*.c)
# all objects
PARSE = $(OBJ_DIR)/parse.o $(OBJ_DIR)/y.tab.o $(OBJ_DIR)/lex.yy.o
IO = $(OBJ_DIR)/client.o $(OBJ_DIR)/fdpool.o
HTTP = $(OBJ_DIR)/http.o $(OBJ_DIR)/cgi.o $(OBJ_DIR)/header.o
OBJ = $(OBJ_DIR)/lisod.o $(IO) $(HTTP) $(PARSE)
# all binaries
BIN := lisod
# C compiler
CC  := gcc
# C PreProcessor Flag
CPPFLAGS := -Iinclude
# compiler flags
CFLAGS   := -g -Wall

default: lisod

$(SRC_DIR)/lex.yy.c: $(SRC_DIR)/lexer.l
	flex -o $@ $^

$(SRC_DIR)/y.tab.c: $(SRC_DIR)/parser.y
	yacc -d $^
	mv y.tab.c $@
	mv y.tab.h $(SRC_DIR)/y.tab.h

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

lisod: $(OBJ) 
	$(CC) -Werror $^ -o $@ -lssl -lcrypto -g

$(OBJ_DIR):
	mkdir $@

clean:
	$(RM) $(OBJ) $(BIN) $(SRC_DIR)/lex.yy.c $(SRC_DIR)/y.tab.*
	$(RM) -r $(OBJ_DIR)
