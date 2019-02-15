import random

template = '''
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define N %d
int main(int argc, char *argv[]) {

  char str[N+1];
  int len;
  fgets(str, N+1, stdin);
  len = strlen(str);

  %s

  assert(0 && "assertion failed");
  return 0;
}

'''

strcmp = '''

  if (len < %d + 1) {
    return 1;
  }

  if (str[%d] != '%c') {
  	printf("failed %d\\n");
  	return 1;
  }
'''

def gen(size):
	code = ''
	choices = [chr(ord('a') + e) for e in range(26)]
	for i in range(size):
		code += (strcmp % (i, i, random.choice(choices), i))
	print(template % (size, code))


if __name__ == '__main__':
	gen(500)