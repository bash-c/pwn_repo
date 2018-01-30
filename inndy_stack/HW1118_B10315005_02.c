#include <stdio.h>

struct stack {
    int n;
    int data[4096];
//    int data[64];
};

void stack_push(struct stack *s, int val) {
    s->data[s->n++] = val;
}

int stack_pop(struct stack *s) {
    return s->data[--s->n];
}

int main () {
    struct stack s = {0};
    char ins[64];
    int n;
    while (scanf("%s", ins) != EOF) {
        switch (ins[0]) {
            case 'i':
                scanf("%d", &n);
                stack_push(&s, n);
                printf("Push %d to stack\n", n);
                break;
            case 'p':
                if (s.n > 0) {
                    printf("Pop -> %d\n", stack_pop(&s));
                } else {
                    printf("Error: stack is empty\n");
                }
//                printf("Pop -> %d\n", stack_pop(&s));
                break;
            case 'c':
                s.n = 0;
                printf("Stack is cleared\n");
                break;
        }
    }
    return 0;
}
