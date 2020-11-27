// gcc -gstabs -c structs.c -o structs.o
struct USER
{
	short int uid;
	char name[256];
	char pwd[256];
	short int isAdmin;
	struct PET *pet;
	struct POST *post;
};

struct PET
{
	int uid;
	char *petName;
	char *petType;
};

struct POST
{
	short int uid;
	char title[256];
	short int nop;
	char *cont;
};

struct HEAD
{
	struct HEAD *next;
	struct USER *u; 
};
