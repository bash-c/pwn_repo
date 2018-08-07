#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEAM_SIZE 8

const int goal = 400;

struct team {
    char* names[MAX_TEAM_SIZE];
    char* strength;
    int teamSize;
} typedef team;

void fight(char* strengths, int teamSize) {
    int sum=0;
    for(int i = 0; i < teamSize; ++i) {
        sum+=strengths[i];
    }

    if(sum == goal) {
        printf("Wow! Your team is strong! Here, take this flag:\n");
        printf("[REDACTED]\n");
    } else {
        printf("Your team had %d strength, but you needed exactly %d!\n",sum,goal);
    }
}

char input[256];

int main() {

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    setbuf(stdout, NULL);

    team t;

    t.teamSize = 0;
    t.strength = malloc(sizeof(int) * MAX_TEAM_SIZE);

    printf("Commands:\n A <name> - Add a team member\n F - Fight the monster\n Q - Quit\n");

    while(1) {
        gets(input,255,stdin);
        if(input[0] == 'A') {
            if(t.teamSize > MAX_TEAM_SIZE) {
                printf("Your team is too large!\n");
            } else {
                t.strength[t.teamSize] = rand() % 10;
                char* newMember = malloc(256);
                strcpy(newMember, &input[2]);
                t.names[t.teamSize] = newMember;
                t.teamSize++;
            }
        } else if (input[0]=='F') {
            fight(t.strength, t.teamSize);
        } else if (input[0]=='Q') {
            printf("Thanks for playing!\n");
            return 0;
        } else {
            printf("Try again\n");
        }
    }
}
