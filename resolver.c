#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_questions_count;
typedef unsigned short dns_flags;

const int TRUE = 1;
const int FALSE = 0;
const int A = 1;
const int CNAME = 5;
const int MAX_WIRE_LENGTH = 2048;
const int MAX_NAME_LENGTH = 256;
const char *PERIOD = ".";
const dns_rr_type TYPE = 1; //Type or Class: Type 1 = IPv4 address, Class 1 = IN, Internet (these can be hardcoded)
const dns_flags FLAGS = 0x0001;
const dns_questions_count NUM_QUESTIONS = 0x0100;
const dns_rr_type RR_TYPE = 0x0100;
const dns_rr_class RR_CLASS = 0x0100;
const int NUM_BYTES_OF_ANSWER_RR = 2;
const int NUM_BYTES_OF_ADDITIONAL_RR = 4;

typedef struct
{
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry
{
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

typedef struct
{
	unsigned char *identification;
	unsigned char *flags;
	unsigned char *questions;
	unsigned char *answer_resource_records;
	unsigned char *authority_additional_resource_records;
	unsigned char *question;
	unsigned char *type_class;
} dns_query_header;

void free_answer_entries(dns_answer_entry *ans)
{
	dns_answer_entry *next;
	while (ans != NULL)
	{
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen)
{
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8)
	{
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	}
	else
	{
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++)
	{
		if (!(i % 8))
		{
			if (i > 0)
			{
				for (j = i - 8; j < i; j++)
				{
					if (j >= byteslen_adjusted)
					{
						printf("  ");
					}
					else if (j >= byteslen)
					{
						printf("  ");
					}
					else if (bytes[j] >= '!' && bytes[j] <= '~')
					{
						printf(" %c", bytes[j]);
					}
					else
					{
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted)
			{
				printf("\n%02X: ", i);
			}
		}
		else if (!(i % 4))
		{
			printf(" ");
		}
		if (i >= byteslen_adjusted)
		{
			continue;
		}
		else if (i >= byteslen)
		{
			printf("   ");
		}
		else
		{
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name)
{
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0)
	{
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.')
	{
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++)
	{
		if (name[i] >= 'A' && name[i] <= 'Z')
		{
			name[i] += 32;
		}
	}
}

void increment_wire_and_len()
{
	//todo
}

int name_ascii_to_wire(char *name, unsigned char *wire)
{
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */

	char *label = strtok(name, PERIOD);
	int wirelen = 0;

	while (label != NULL)
	{
		// printf("label: %s\n", label);

		int labellen = strlen(label);

		*wire = (unsigned char)labellen; //Before each label, a single byte is used that holds a number indicating the number of characters in the label
		wire++;							 //Go to the next byte
		wirelen++;						 //Wire is now one bit long

		for (int i = 0; i < labellen; i++) //Then, the label's characters are encoded, one per byte
		{
			*wire = (unsigned char)label[i];
			wire++;	   //Go to the next byte
			wirelen++; //Wire is now one bit long
		}

		label = strtok(NULL, PERIOD);
	}

	*wire = 0x00; //The end of the name is indicated by a null label, representing the root
	wire++;
	wirelen++;

	return wirelen;
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp)
{
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
	printf("name_ascii_from_wire() start\n");
	printf("initial *indexp: %d\n", *indexp);

	char name[MAX_NAME_LENGTH];
	int string_index = 0;

	unsigned char name_index = *indexp;
	// printf("name_index: %d\n", name_index);
	// while (wire[name_index] >= 192) //We are still a compressed string, next byte will be a pointer
	// {
	// 	name_index += 1; //Looking at the pointer
	// 	name_index = wire[name_index];
	// 	printf("name_index: %d\n", name_index);
	// }

	while (wire[name_index] > 0)
	{
		while (wire[name_index] >= 192) //We are still a compressed string, next byte will be a pointer
		{
			name_index += 1; //Looking at the pointer
			name_index = wire[name_index];
			printf("name_index: %d\n", name_index);
		}
		int num_byte_to_read = wire[name_index];
		name_index += 1;

		printf("\nNumber of bytes to read: %d\n", num_byte_to_read);

		for (int i = 0; i < num_byte_to_read; i++)
		{
			printf("index: %d\n", name_index);
			// printf("char to add: %c\n", wire[name_index]);
			name[string_index + i] = wire[name_index];
			name_index += 1;
			// printf("name so far: %s\n", name);
		}

		string_index += num_byte_to_read;
		name[string_index] = '.';
		string_index += 1;

		break;
	}

	name[string_index - 1] = 0x00; //for the last char of the string it should be 0x00, not '.'
	printf("Final name: %s\n", name);

	*indexp += 2;
	printf("indexp: %d\n", *indexp);
	printf("name_index: %d\n", name_index);

	char *ret = (char *)malloc(strlen(name) + 1);

	//copy string
	for (int i = 0; i < strlen(name); i++)
	{
		ret[i] = name[i];
	}
	ret[strlen(name)] = '\0';

	printf("Final ret string name: %s\n", name);
	printf("name_ascii_from_wire() finissssssssssshhhh\n");

	return ret;
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only)
{
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */

	printf("rr_from_wire() start\n");

	dns_rr rr;

	rr.name = name_ascii_from_wire(wire, indexp);
	printf("\nname: %s\n", rr.name);

	rr.type = wire[*indexp + 1] | wire[*indexp] << 8;
	*indexp += 2;

	rr.class = wire[*indexp + 1] | wire[*indexp] << 8;
	*indexp += 2;

	// rr.ttl = NULL; //Time To Live: Indicates how long this record should stay in the resolver’s cache (you resolver doesn’t have a cache, so don’t worry about this) (skip 4)
	*indexp += 4;

	rr.rdata_len = wire[*indexp + 1] | wire[*indexp] << 8;
	*indexp += 2;

	unsigned char *data = (unsigned char *)malloc(rr.rdata_len);

	if (rr.type == A)
	{
		printf("rr.type == A (or 1, or IPv4)\n");
		for (int i = 0; i < rr.rdata_len; i++)
		{
			data[i] = wire[(*indexp)];
			*indexp += 1;
		}
	}
	else if (rr.type == CNAME)
	{
		printf("rr.type == CNAME (or 5)\n");
		data = (unsigned char *)name_ascii_from_wire(wire, indexp);
		//todo do I need a cast here
	}
	else
	{
		fprintf(stderr, "Unknown record type: %d\n", rr.type);
	}

	rr.rdata = data;

	// printf("rr.rdata: %s\n", data);

	//We done here
	printf("rr_from_wire() end\n");
	return rr;
}

int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only)
{
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */

	int wirelen = 0;

	if (query_only == TRUE)
	{
		*wire = *((unsigned char *)&rr.class);
		wire++;
		wirelen++;
		*wire = *((unsigned char *)&rr.class + 1);
		wire++;
		wirelen++;

		*wire = *((unsigned char *)&rr.type);
		wire++;
		wirelen++;
		*wire = *((unsigned char *)&rr.type + 1);
		wire++;
		wirelen++;
	}
	else
	{
		fprintf(stderr, "rr_to_wire() on not query only");
	}

	return wirelen;
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */

	int wirelen = 0;
	srand((unsigned int)time(NULL));

	//Identification: These 2 bytes are randomly generated
	*wire = (unsigned char)rand();
	wire++;
	wirelen++;
	*wire = (unsigned char)rand();
	wire++;
	wirelen++;

	//Flags: Each bit represents a flag or code (not important for this lab, can be hardcoded)
	*wire = *((unsigned char *)&FLAGS);
	wire++;
	wirelen++;
	*wire = *((unsigned char *)&FLAGS + 1);
	wire++;
	wirelen++;

	//Number of questions
	*wire = *((unsigned char *)&NUM_QUESTIONS);
	wire++;
	wirelen++;
	*wire = *((unsigned char *)&NUM_QUESTIONS + 1);
	wire++;
	wirelen++;

	//Number of Answer Resource Records (RR): 0
	for (int i = 0; i < NUM_BYTES_OF_ANSWER_RR; i++)
	{
		*wire = 0x00;
		wire++;
		wirelen++;
	}

	//Number of Authority/Additional Resource Records (RR): these will always be 0 for this lab
	for (int i = 0; i < NUM_BYTES_OF_ADDITIONAL_RR; i++)
	{
		*wire = 0x00;
		wire++;
		wirelen++;
	}

	//Question: the formatted domain name
	int namelen = name_ascii_to_wire(qname, wire);
	//todo: do we need to check if len == NULL???
	wire += namelen;
	wirelen += namelen;

	//Type/Class
	dns_rr rr;
	rr.class = RR_CLASS;
	rr.type = RR_TYPE;

	int rrlen = rr_to_wire(rr, wire, TYPE);
	//todo: do we need to check if len == NULL???
	wire += rrlen;
	wirelen += rrlen;

	//We're done here
	return wirelen;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */

	printf("get_answer_address() start\n");

	int byteIndex = 0;

	//Skip: identification (+2), flags (+2), and questions (+2) to arrive at number of answer rr
	byteIndex += 6;

	//Get number of answers
	int answerslen = wire[byteIndex + 1] | wire[byteIndex] << 8;
	byteIndex += 2;
	// printf("\nNum answers: %d\n", answerslen);

	//Skip: authority rr (+2) and additional rr (+2) - The number of authority and additional RR’s in the wire (these will always be 0 for this lab)
	byteIndex += 4;

	//Skip the question
	while (wire[byteIndex] != 0x00)
	{
		byteIndex += 1;
	}
	byteIndex += 1;

	//Skip the type
	byteIndex += 2;

	//Skip the class
	byteIndex += 2;

	dns_rr resource_records[answerslen];

	for (int i = 0; i < answerslen; i++)
	{
		printf("i = %d\n", i);
		printf("rr_from_wire() call from resource_records[] pop\n");
		resource_records[i] = rr_from_wire(wire, &byteIndex, FALSE);
	}

	dns_answer_entry *first_answer_entry = NULL;
	dns_answer_entry *next_temp_entry = NULL;

	for (int i = 0; i < answerslen; i++) //todo change this
	{

		if (i == 0)
		{
			next_temp_entry = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
			first_answer_entry = next_temp_entry;
		}
		else
		{
			next_temp_entry->next = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
			next_temp_entry = next_temp_entry->next;

			next_temp_entry->next = NULL;
		}

		if (resource_records[i].type == A)
		{
			next_temp_entry->value = (char *)malloc(INET_ADDRSTRLEN);
			inet_ntop(AF_INET, resource_records[i].rdata, next_temp_entry->value, INET_ADDRSTRLEN);
		}
		else if (resource_records[i].type == CNAME)
		{ //Name is an alias
			canonicalize_name((char *)resource_records[i].rdata);
			next_temp_entry->value = (char *)resource_records[i].rdata;
		}
	}

	printf("get_answer_address() start\n");
	return first_answer_entry;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port)
{
	/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		fprintf(stderr, "Socket failed to be created");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_addr.s_addr = inet_addr(server);
	servaddr.sin_port = htons(port);
	servaddr.sin_family = AF_INET;

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		fprintf(stderr, "Socket could not connect");
		exit(EXIT_FAILURE);
	}

	int writelen = write(sockfd, request, requestlen);
	if (writelen != requestlen)
	{
		fprintf(stderr, "Socket could not write completly");
		exit(EXIT_FAILURE);
	}

	int readlen = read(sockfd, response, MAX_WIRE_LENGTH);
	if (readlen < 0)
	{
		fprintf(stderr, "Socket could not read");
		exit(EXIT_FAILURE);
	}

	return readlen;
}

dns_answer_entry *resolve(char *qname, char *server, char *port)
{
	unsigned char request_wire[MAX_WIRE_LENGTH];

	printf("Request wire:\n");
	print_bytes(request_wire, 22);

	int request_wirelen = create_dns_query(qname, TYPE, request_wire);

	// print_bytes(request_wire, request_wirelen);

	unsigned char response_wire[MAX_WIRE_LENGTH];

	// print_bytes(response_wire, 200);

	int response_wirelen = send_recv_message(request_wire, request_wirelen, response_wire, server, atoi(port));

	printf("Response wire:\n");
	print_bytes(response_wire, response_wirelen);

	return get_answer_address(qname, TYPE, response_wire);
}

int main(int argc, char *argv[])
{
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3)
	{
		port = argv[3];
	}
	else
	{
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL)
	{
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL)
	{
		free_answer_entries(ans_list);
	}
}
