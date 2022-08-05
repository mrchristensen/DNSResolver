# DNS Resolver

This project uses sockets to create a basic DNS stub resolver.

Functionality includes:
- Formating the question into a DNS query of the proper format
- Sending the query to a designated recursive DNS server
- Waiting for and receive the response from the server
- Extracting the answer from the response and return it to the caller

For the implementation, see [resolver.c](resolver.c).
For more information about the project, see [dnsresolver.pdf](dnsresolverlab.pdf)
