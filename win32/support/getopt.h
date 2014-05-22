
#define _next_char(string)  (char)(*(string+1))

extern char * optarg; 
extern int    optind; 

int getopt(int, char**, char*);

