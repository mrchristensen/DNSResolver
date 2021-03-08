#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
const int MAX_WIRE_LENGTH = 2048;
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
		printf("label: %s\n", label);

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
	*wire = FLAGS;
	wire += sizeof(FLAGS);
	wirelen += sizeof(FLAGS);

	//Number of questions
	*wire = NUM_QUESTIONS;
	wire += sizeof(NUM_QUESTIONS);
	wirelen += sizeof(NUM_QUESTIONS);

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
}

dns_answer_entry *resolve(char *qname, char *server, char *port)
{
	unsigned char wire[MAX_WIRE_LENGTH];

	int wirelen = create_dns_query(qname, TYPE, wire);

	print_bytes(wire, wirelen);
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
