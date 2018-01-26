#include <stdio.h>
#include <string.h>

struct NOTE {
    struct NOTE* next;
    char         data[128];
};

int read_integer()
{
    char buff[8];
    fgets(buff, sizeof(buff) - 1, stdin);
    return atoi(buff);
}

struct NOTE * find_node_by_id(struct NOTE *node, int id)
{
    int n = id;

    // find n-th available note
    while(node->next && n-- > 0) {
        node = node->next;
    }
    if(n > 0) {
        printf("Can not found note with id %d\n", id);
        return NULL;
    } else {
        return node;
    }
}

void add_note(struct NOTE *node)
{
    int id = 0;
    // find node empty node
    while(node->next && node->data[0]) {
        node = node->next;
        id++;
    }
    printf("Input your note: ");
    fgets(node->data, sizeof(node->data), stdin);
    // do not waste memory :)
    node->next = (struct NOTE*)(node->data + strlen(node->data) + 1);
    node->next->data[0] = '\0'; // mark as unused

    printf("Ok! Your note id is %d\n", id);
}

void edit_note(struct NOTE *node)
{
    printf("Which note to edit: ");
    int id = read_integer();
    node = find_node_by_id(node, id);
    if(!node) return;

    printf("Your new data: ");
    // gets is dangrous! fgets is safe
    fgets(node->data, sizeof(node->data), stdin);
    puts("Done!");
}

void print_note(struct NOTE *node, int id)
{
    printf("Note id  : %d\n", id);
    printf("Next note: %p\n", node->next);
    printf("Note data: %s\n", node->data);
    puts("----------------");
}

void show_note(struct NOTE *node)
{
    printf("Which note to show: ");
    int id = read_integer();
    node = find_node_by_id(node, id);
    if(!node) return;
    print_note(node, id);
}

void dump_notes(struct NOTE *node)
{
    int id = 0;
    while(node && node->data[0]) {
        print_note(node, id++);
        puts("");
        node = node->next;
    }
}

int choose()
{
    puts("1) add note");
    puts("2) edit note");
    puts("3) show note");
    puts("4) dump notes");
    puts("5) exit");
    printf("Your action: ");
    return read_integer();
}

void vuln()
{
    int loop_switch = 1;
    struct NOTE buffer[128];

    memset(buffer, 0, sizeof(buffer));

    while(loop_switch) {
        switch(choose()) {
            case 1:
                add_note(buffer);
                break;
            case 2:
                edit_note(buffer);
                break;
            case 3:
                show_note(buffer);
                break;
            case 4:
                dump_notes(buffer);
                break;
            case 5:
                loop_switch = 0;
                break;
            default:
                puts("Invalid option!");
        }
    }
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("Hello, Welcome to Very Overflow Notes System");
    vuln();
    return 0;
}

// gcc very_overflow.c -m32 -o very_overflow -fno-stack-protector -g
