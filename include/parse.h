#ifndef PARSE_H
#define PARSE_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "header.h"

#define SUCCESS 0
#define BAD_REQ -1
#define REQ_UNFIN 1

Request *parse(char *buffer, int size, size_t *offset, int *ret) ;
// functions decalred in parser.y
int yyparse();
void set_parsing_options(char *buf, size_t i, Request *request);

#endif