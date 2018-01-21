#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct record {
	void (*print)(struct record *);
	void (*free)(struct record *);
	union {
		int integer;
		char *string;
	};
};

struct record *records[16];

int ask(const char * q)
{
	char buff[32];
	printf("%s > ", q);
	fgets(buff, sizeof(buff), stdin);
	return atoi(buff);
}

void rec_int_print(struct record *rec)
{
	printf("Record(Type=Integer, Value=%d)\n", rec->integer);
}

void rec_str_print(struct record *rec)
{
	printf("Record(Type=String, Value=%s)\n", rec->string);
}

void rec_int_free(struct record *rec)
{
	free(rec);
	puts("Record freed!");
}

void rec_str_free(struct record *rec)
{
	free(rec->string);
	free(rec);
	puts("Record freed!");
}

void do_new()
{
	int idx = ask("Index");

	if(idx < 0 || idx > 16) {
		puts("Out of index!");
		return;
	}
	if(records[idx]) {
		printf("Index #%d is used!\n", idx);
		return;
	}

	struct record *r = records[idx] = (struct record *)malloc(sizeof(struct record));
	r->print = rec_int_print;
	r->free = rec_int_free;

	puts("Blob type:");
	puts("1. Integer");
	puts("2. Text");
	int type = ask("Type");
	unsigned int len;

	switch(type) {
		case 1:
			r->integer = ask("Value");
			break;
		case 2:
			len = ask("Length");
			if(len > 1024) {
				puts("Length too long, please buy record service premium to store longer record!");
				return;
			}
			r->string = malloc(len);
			printf("Value > ");
			fgets(r->string, len, stdin);
			r->print = rec_str_print;
			r->free = rec_str_free;
			break;
		default:
			puts("Invalid type!");
			return;
	}

	puts("Okey, we got your data. Here is it:");
	r->print(r);
}

void do_del()
{
	int idx = ask("Index");
	records[idx]->free(records[idx]);
}

void do_dump()
{
	int idx = ask("Index");
	records[idx]->print(records[idx]);
}

int main()
{
	alarm(600);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	puts("Welcome to use my Record-as-a-Service (free plan)");
	puts("You can only save Integer or String for 600 seconds");
	puts("Pay 1,000,000,000,000,000,000,000,000 bitcoins to buy premium plan");

	puts("Here is term of service. You must agree to use this service. Please read carefully!");
	puts("================================================================================");
	system("cat tos.txt | head -n 30 | sed -e 's/^/    /'");
	puts("================================================================================");


	while(1) {
		puts("1. New record");
		puts("2. Del record");
		puts("3. Show record");

		switch(ask("Act")) {
			case 1:
				do_new();
				break;
			case 2:
				do_del();
				break;
			case 3:
				do_dump();
				break;
			default:
				puts("Bye~ Thanks for using our service!");
				return 0;
		}
	}
}
