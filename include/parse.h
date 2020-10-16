#ifndef PARSE_H
#define PARSE_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SUCCESS 0
#define BAD_REQ 1
#define REQ_UNFIN 2

//Header field
typedef struct
{
	char header_name[4096];
	char header_value[4096];
} Request_header;

//HTTP Request Header
typedef struct
{
	char http_version[50];
	char http_method[50];
	char http_uri[4096];
	Request_header *headers;
	int header_count;
	int header_capacity ;
} Request;

Request *parse(char *buffer, int size, size_t *offset, int *ret) ;

// functions decalred in parser.y
int yyparse();
void set_parsing_options(char *buf, size_t i, Request *request);

#endif