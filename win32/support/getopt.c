
#include <stdio.h>                  /* for EOF */ 
#include <string.h>                 /* for strchr() */ 

#include <getopt.h> 
 
/* static (global) variables that are specified as exported by getopt() */ 
char *optarg = NULL;    /* pointer to the start of the option argument  */ 
int   optind = 1;       /* number of the next argv[] to be evaluated    */ 
int   opterr = 1;       /* non-zero if a question mark should be returned 
                           when a non-valid option character is detected */

int getopt(int argc, char *argv[], char *opstring) { 
  static char *pIndexPosition = NULL; /* place inside current argv string */ 
  char *pArgString = NULL;        /* where to start from next */ 
  char *pOptString;               /* the string in our program */ 
 
  if (pIndexPosition != NULL) { 
    /* we last left off inside an argv string */ 
    if (*(++pIndexPosition)) { 
      /* there is more to come in the most recent argv */ 
      pArgString = pIndexPosition; 
    } 
  } 
 
  if (pArgString == NULL) { 
    /* we didn't leave off in the middle of an argv string */ 
    if (optind >= argc) { 
      /* more command-line arguments than the argument count */ 
      pIndexPosition = NULL;  /* not in the middle of anything */ 
      return EOF;             /* used up all command-line arguments */ 
    } 
 
    /*--------------------------------------------------------------------- 
     * If the next argv[] is not an option, there can be no more options. 
     *-------------------------------------------------------------------*/ 
    pArgString = argv[optind++]; /* set this to the next argument ptr */ 
 
    if (('/' != *pArgString) && /* doesn't start with a slash or a dash? */ 
	('-' != *pArgString)) { 
      --optind;               /* point to current arg once we're done */ 
      optarg = NULL;          /* no argument follows the option */ 
      pIndexPosition = NULL;  /* not in the middle of anything */ 
      return EOF;             /* used up all the command-line flags */ 
    } 

    /* check for special end-of-flags markers */ 
    if ((strcmp(pArgString, "-") == 0) || 
	(strcmp(pArgString, "--") == 0)) { 
      optarg = NULL;          /* no argument follows the option */ 
      pIndexPosition = NULL;  /* not in the middle of anything */ 
      return EOF;             /* encountered the special flag */ 
    } 
 
    pArgString++;               /* look past the / or - */ 
  } 
 
  if (':' == *pArgString) {       /* is it a colon? */ 
    /*--------------------------------------------------------------------- 
     * Rare case: if opterr is non-zero, return a question mark; 
     * otherwise, just return the colon we're on. 
     *-------------------------------------------------------------------*/ 
    return (opterr ? (int)'?' : (int)':'); 
  } else if ((pOptString = strchr(opstring, *pArgString)) == 0) { 
    /*--------------------------------------------------------------------- 
     * The letter on the command-line wasn't any good. 
     *-------------------------------------------------------------------*/ 
    optarg = NULL;              /* no argument follows the option */ 
    pIndexPosition = NULL;      /* not in the middle of anything */ 
    return (opterr ? (int)'?' : (int)*pArgString); 
  } else { 
    /*--------------------------------------------------------------------- 
     * The letter on the command-line matches one we expect to see 
     *-------------------------------------------------------------------*/ 
    if (':' == _next_char(pOptString)) { /* is the next letter a colon? */ 
      /* It is a colon.  Look for an argument string. */ 
      if ('\0' != _next_char(pArgString))  /* argument in this argv? */ 
	optarg = &pArgString[1];   /* Yes, it is */ 
      else { 
	/*------------------------------------------------------------- 
	 * The argument string must be in the next argv. 
	 * But, what if there is none (bad input from the user)? 
	 * In that case, return the letter, and optarg as NULL. 
	 *-----------------------------------------------------------*/ 
	if (optind < argc) 
	  optarg = argv[optind++]; 
	else { 
	  optarg = NULL; 
	  return (opterr ? (int)'?' : (int)*pArgString); 
	} 
      } 

      pIndexPosition = NULL;  /* not in the middle of anything */ 
    } else { 
      /* it's not a colon, so just return the letter */ 
      optarg = NULL;          /* no argument follows the option */ 
      pIndexPosition = pArgString;    /* point to the letter we're on */ 
    } 
    return (int)*pArgString;    /* return the letter that matched */ 
  } 
}
