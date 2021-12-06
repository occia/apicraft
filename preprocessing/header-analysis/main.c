#include "stdio.h"

struct A {
    short a0;
    unsigned int b1 : 3;
    unsigned int b2 : 1;
    int a1;
    int *a2;
};

struct A;

typedef struct A A;

typedef struct A* Aref;


enum B {
    b1,
    b2,
    b3,
};

static enum B heihei = b2;

Aref haha(A *a, int*b);
void hehe(A *a, int*b);
void hihi(A *a, enum B);

int main () 
{
    A *a;
    printf("hehe %u\n", sizeof(a));
}
