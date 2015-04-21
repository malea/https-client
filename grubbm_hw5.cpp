/* Network Programming Homework 5: MALEA GRUBB*/

#include <string.h>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <memory>
#include <errno.h>

#define DEBUG

using namespace std;

string get_perror() {
  return string(strerror(errno));
}

const char *openssl_strerror( ) {
	return ERR_error_string(ERR_get_error(), NULL);
}

class Connection {
  public:

    // Dynamic dispatch get function.
    // Chooses the correct subclass based on url.
    // Assigns the response to `response`.
    // If error, returns false and sets `error`.
    static bool smart_get(
        const string &url,
        string *response,
        string *error);

    // Initialize the connection.
    virtual bool connect(
        const string &host,
        const string &port,
        string *error) {
      error->assign("abstract - not implemented");
      return false;
    }

    // Close the connection.
    virtual bool close(string *error) {
      error->assign("abstract - not implemented");
      return false;
    }

  protected:
    // Send packet over the connection.
    virtual bool send(const string &packet, string *error) {
      error->assign("abstract - not implemented");
      return false;
    }

    // Receive packet over the connection.
    virtual bool recv(string *packet, string *error) {
      error->assign("abstract - not implemented");
      return false;
    }

    virtual string default_port() {
      return "80";
    }

  private:
    // Choose the right connection subclass based on the url.
    static Connection *make_connection(const string &url);

    // Private implementation of `get` function.
    bool get(
        const string &url,
        string *response,
        string *error);

    // Parse the given URL.
    bool parse_url(
        const string &url,
        string *host,
        string *port,
        string *path,
        string *error);

    // Put the GET request into `request`.
    static bool construct_request(
        const string &host,
        const string &port,
        const string &path,
        string *request,
        string *error);
};

class HttpConnection : public Connection {
  public:
    bool connect(
        const string &host,
        const string &port,
        string *error) override;
    bool close(string *error) override;
  protected:
    bool send(const string &packet, string *error) override;
    bool recv(string *packet, string *error) override;
    string default_port() override {
      return "80";
    }
  private:
    int sockfd_;
};

class HttpsConnection : public Connection {
  public:
    bool connect(
        const string &host,
        const string &port,
        string *error) override;
    bool close(string *error) override;
  protected:
    bool send(const string &packet, string *error) override;
    bool recv(string *packet, string *error) override;
    string default_port() override {
      return "443";
    }
  private:
    SSL_CTX *ctx_;
    BIO *conn_;
};

bool Connection::parse_url(
    const string &url,
    string *host,
    string *port,
    string *path,
    string *error) {

  bool port_included = false;
  port->assign("");
  host->assign("");
  path->assign("");

  static const string sep = "://";
  size_t sep_index = url.find(sep);
  size_t count = sep_index + sep.size();
  
  // parse host from url
  while (count != url.size()) {
    if (url[count] == ':') {
      count++;
      port_included = true;
      break;
    }
    else if (url[count] == '/') {
      break;
    }
    else {
      *host += url[count];
      count++;
    }
  }

  // parse port from url
  while (port_included && count != url.size()) {
    if (url[count] == '/') {
      break;
    }
    *port += url[count];
    count++;
  }

  // parse path from url
  while (count != url.size()) {
    *path += url[count]; 
    count++;
  }

  if (*path == "" || *host == "") {
    error->assign("invalid url");
    return false;
  }

  // if port not included, set to null so we know to use default
  if (!port_included) {
    port->assign(default_port());
  } 

  return true;
}

bool Connection::construct_request(
    const string &host,
    const string &port,
    const string &path,
    string *request,
    string *error) {
  string r = "GET " + path + " HTTP/1.1\r\n";
  string headers = "Host: " + host + ":" + port+ "\r\nConnection: close\r\nUser-Agent: grubbm_hw/1.0\r\n\r\n";
  string send_this = r + headers;
  request->assign(send_this);
  return true;
}

bool Connection::get(
    const string &url,
    string *response,
    string *error) {

  string host;
  string port;
  string path;
  if (!parse_url(url, &host, &port, &path, error)) {
    return false;
  }

#ifdef DEBUG
  cout << "Parsed url." <<endl;
  cout << "url: " << url << endl;
  cout << "host: " << host << endl;
  cout << "port: " << port << endl;
  cout << "path: " << path << endl;
#endif

  if (!connect(host, port, error)) {
    return false;
  }

#ifdef DEBUG
  cout << "Successfully connected." << endl;
#endif

  string request;
  if (!construct_request(host, port, path, &request, error)) {
    return false;
  }

#ifdef DEBUG
  cout << "Constructed request:" << endl;
  cout << "==== <REQUEST> ====" << endl;
  cout << request;
  cout << "==== </REQUEST> ====" << endl;
#endif

  if (!send(request, error)) {
    return false;
  }

#ifdef DEBUG
  cout << "Request sent to server." << endl;
#endif

  if (!recv(response, error)) {
    return false;
  }

#if 0
  cout << "Response received from server:" << endl;
  cout << "==== <RESPONSE> ====" << endl;
  cout << *response;
  cout << "==== </RESPONSE> ====" << endl;
#endif

  return true;
}

/* Helper Function to create the SSL context...taken from in-class notes :) */
SSL_CTX *create_ssl_context( ) {
	SSL_CTX *ret;

	/* create a new SSL context */
	ret = SSL_CTX_new(SSLv23_client_method( ));
	
	if (ret == NULL) {
		fprintf(stderr, "SSL_CTX_new failed!\n");
		return NULL;
	}

	/* 
	 * set our desired options 
	 *
	 * We don't want to talk to old SSLv2 or SSLv3 servers because
	 * these protocols have security issues that could lead to the
	 * connection being compromised. 
	 *
	 * Return value is the new set of options after adding these 
	 * (we don't care).
	 */
	SSL_CTX_set_options(
		ret, 
		SSL_OP_NO_SSLv2 | 
		SSL_OP_NO_SSLv3 |
		SSL_OP_NO_COMPRESSION
	);

	/*
	 * set up certificate verification
	 *
	 * We want the verification to fail if the peer doesn't 
	 * offer any certificate. Otherwise it's easy to impersonate
	 * a legitimate server just by offering no certificate.
	 *
	 * No error checking, not because I'm being sloppy, but because
	 * these functions don't return error information.
	 */
	SSL_CTX_set_verify(
		ret, 
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		NULL
	);
	SSL_CTX_set_verify_depth(ret, 4);

	/*
	 * Point our context at the root certificates.
	 * This may vary depending on your system.
	 */
	if (SSL_CTX_load_verify_locations(ret, NULL, "/etc/ssl/certs") == 0) {
		fprintf(stderr, "Failed to load root certificates\n");
		SSL_CTX_free(ret);	
		return NULL;
	}

	return ret;
}

BIO *open_ssl_connection(SSL_CTX *ctx, const char *server) {
	BIO *ret;

	/* use our settings to create a BIO */
	ret = BIO_new_ssl_connect(ctx);
	if (ret == NULL) {
		fprintf(	
			stderr, 
			"BIO_new_ssl_connect failed: %s\n",
			openssl_strerror( )
		);
		return NULL;
	}

	/* according to documentation, this cannot fail */
	BIO_set_conn_hostname(ret, server);

	/* try to connect */
	if (BIO_do_connect(ret) != 1) {
		fprintf(stderr, 
			"BIO_do_connect failed: %s\n",
			openssl_strerror( )
		);

		BIO_free_all(ret);	
		return NULL;
	}

	/* try to do TLS handshake */
	if (BIO_do_handshake(ret) != 1) {
		fprintf(
			stderr, 
			"BIO_do_handshake failed: %s\n",
			openssl_strerror( )
		);

		BIO_free_all(ret);
		return NULL;
	}

	return ret;
}

int check_certificate(BIO *conn, const char *hostname) {
	SSL *ssl;
	X509 *cert;
	X509_NAME *subject_name;
	X509_NAME_ENTRY *cn;
	ASN1_STRING *asn1;
	unsigned char *cn_str;
	int pos;
	bool hostname_match;

	/* get this particular connection's TLS/SSL data */
	BIO_get_ssl(conn, &ssl);
	if (ssl == NULL) {
		fprintf(
			stderr, "BIO_get_ssl failed: %s\n",
			openssl_strerror( )
		);

		return -1;
	}

	/* get the connection's certificate */
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		/* no certificate was given - failure */
		return -1;
	}

	/* check that the certificate was verified */
	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		/* certificate was not successfully verified */
		return -1;
	}

	/* get the name of the certificate subject */
	subject_name = X509_get_subject_name(cert);
	
	/* and print it out */
	X509_NAME_print_ex_fp(stderr, subject_name, 0, 0);

	/* loop through "common names" (hostnames) in cert */
	pos = -1;
	hostname_match = false;
	for (;;) {
		/* move to next CN entry */
		pos = X509_NAME_get_index_by_NID(
			subject_name, NID_commonName, pos
		);

		if (pos == -1) { 
			break;
		}

		cn = X509_NAME_get_entry(subject_name, pos);
		asn1 = X509_NAME_ENTRY_get_data(cn);
		if (ASN1_STRING_to_UTF8(&cn_str, asn1) < 0) {
			fprintf(
				stderr, "ASN1_STRING_to_UTF8 failed: %s",
				openssl_strerror( )
			);
			return -1;
		}

		/* finally we have a hostname string! */
		if (strcmp((char *) cn_str, hostname) == 0) {
			hostname_match = true;
		}
	}

	if (hostname_match) {
		return 0;
	} else {
		fprintf(stderr, "hostnames do not match!\n");
		return -1;
	}
}

bool HttpsConnection::connect(
    const string &host,
    const string &port,
    string *error) {
  // initialize OpenSSL
  SSL_library_init();
  SSL_load_error_strings();

  // create the OpenSSL context
  ctx_ = create_ssl_context();
  if (ctx_ == NULL) {
    error->assign("create ssl context failed");
    return false;
  }

  // try to open an SSL connection
  string destination = host + ":" + port;
  conn_ = open_ssl_connection(ctx_, destination.c_str()); 
  if (conn_ == NULL) {
    error->assign("failed to create ssl connection");
    return false;
  }

  if (check_certificate(conn_, host.c_str()) != 0) {
    error->assign("certificate tests failed!");
    return false;
  }
  return true;
}

bool HttpsConnection::close(string *error) {
  BIO_free_all(conn_);
  return true;
}

bool HttpsConnection::send(const string &packet, string *error) {
  BIO_puts(conn_, packet.c_str());
  return true;
}

bool HttpsConnection::recv(string *packet, string *error) {
  int size;
  char buf[2048];

  do {
    size = BIO_read(conn_, buf, 2048);
    if (size > 0) {
      fwrite(buf, 1, size, stdout);
    }
  } while (size > 0 || BIO_should_retry(conn_));
  return true;
}

bool HttpConnection::connect(
    const string &host,
    const string &port,
    string *error) {
  sockfd_ = socket(AF_INET6, SOCK_STREAM, 0);
  if (sockfd_ == -1) {
    error->assign("socket failure: " + get_perror());
    return false;
  }

  struct addrinfo ai_hints;
  struct addrinfo *ai_results;

  memset(&ai_hints, 0, sizeof(ai_hints));
  ai_hints.ai_family = AF_INET6;
  ai_hints.ai_socktype = SOCK_STREAM;
  ai_hints.ai_flags = AI_ALL | AI_V4MAPPED | AI_ADDRCONFIG;

  int gai_ret = getaddrinfo(host.c_str(), port.c_str(), &ai_hints, &ai_results);
  if (gai_ret != 0) {
    error->assign("getaddrinfo: " + string(gai_strerror(gai_ret)));
    return false;
  }

  // Loop through the addresses and try to connect() to each until one that works is found.
  bool success = false;
  for (struct addrinfo *j = ai_results; j != NULL; j = j->ai_next) {
    if(::connect(sockfd_, j->ai_addr, j->ai_addrlen) == 0) {
      success = true; // a connection has successfully been made!
      break;
    }
  } 

  // clean up ai_results
  freeaddrinfo(ai_results);

  if (!success) {
    error->assign("connect failure: " + get_perror());
    return false;
  }

  return true;
}

bool HttpConnection::close(string *error) {
  ::close(sockfd_);
  return true;
}

bool HttpConnection::send(const string &packet, string *error) {
  ssize_t ret, sent = 0;
  size_t size = packet.size();
  int flags = 0;
  uint8_t *bytes = (uint8_t *)packet.c_str();
  
  while (size > 0) {
    ret = ::send(sockfd_, bytes, size, flags);

    if (ret < 0) {
      error->assign("send error: " + get_perror());
      return false;
    }
    size -= ret;
    bytes += ret;
    sent += ret;
  }
  return true;
}

/* This function receives from the socket and puts a complete line in line and places
   the remaining content into the backlog */
void get_line(int fd, string backlog, string &line, string &new_backlog) {
  // check to see if there is a line break in backlog
  int end_of_line = backlog.find("\r\n");
  // if there is, return that line
  if (end_of_line != string::npos) {
    line = backlog.substr(0,end_of_line);
    new_backlog = backlog.substr(end_of_line + 2);
    return;
  }
  char buff[1024];
  char *rest;
  int buffsize;
  new_backlog = backlog;
  // otherwise, we have more the receive
  while (true) {
    buffsize = recv(fd, buff, sizeof(buff), 0);
    if (buffsize < 0) {
      perror("recv");
      exit(1);
    }
    // check for line break
    rest = strstr(buff, "\r\n");
    if (rest != NULL) {
      break; // we are done
    }
    // if no line break, add buff to the new backlog
    new_backlog += string(buff); 
  }
  rest[0] = '\0';
  // first, set the line to the line we found
  line = new_backlog + string(buff);
  // then, handle the remaining received bytes and put them in new_backlog
  int length_of_rest = buffsize - strlen(buff) - 2;
  if (length_of_rest >= 1) {
    new_backlog = string(rest + 2, length_of_rest);
  }
  else {
    new_backlog = "";
  }
}

bool HttpConnection::recv(string *packet, string *error) {
  string backlog = "";
  int content_length = -1;
  const string pattern = "Content-Length: ";
  // first get headers, line-by-line
  while (true) {
    string line, new_backlog;
    get_line(sockfd_, backlog, line, new_backlog);
    if (line == "") {
      break;
    }
    // print header lines to stderr
    cerr << line << endl;

    // if line starts with "Content-Length: "
    // parse it and put it in content_length
    string maybe_content_length = line.substr(0,pattern.size());
    if (maybe_content_length == pattern) {
      content_length = atoi(line.substr(pattern.size()).c_str()); 
    }

    backlog = new_backlog;
  }
  // if Content-Length is not provided in response, inform and exit
  if (content_length == -1) {
    error->assign("Content-Length not provided in response!");
    return false;
  }
  // print out blank line to separate headers (in stderr) from body (in stdout)
  cout << endl; 

  // now print out backlog
  cout << backlog;

  // now it is known exactly how much is left to receive, receive it in body_buf
  int remaining_to_recv = content_length - backlog.size() + 1;
  char body_buf[remaining_to_recv];

  while (remaining_to_recv > 0) {
    int ret = ::recv(sockfd_, body_buf, remaining_to_recv, 0);
    if (ret < 0) {
      error->assign("recv: " + get_perror());
      return false;
    }
    if (ret == 0) {
      break;
    }
    // print out body to stdout
    fwrite(body_buf, sizeof(char), ret, stdout);
    remaining_to_recv -= ret;
  }
  return true;
}

Connection *Connection::make_connection(const string &url) {
  if (url.substr(0, 5) == "https") {
#ifdef DEBUG
    cout << "Using HTTPS connection class." << endl;
#endif
    return new HttpsConnection();
  } else {
#ifdef DEBUG
    cout << "Using HTTP connection class." << endl;
#endif
    return new HttpConnection();
  }
}

bool Connection::smart_get(
    const string &url,
    string *response,
    string *error) {
  unique_ptr<Connection> conn(make_connection(url));
  conn->get(url, response, error);
}

int main(int argc, char *argv []) {
  if (argc != 2) {
    cerr << "Wrong Number of Arguments! Please supply a URL" << endl; 
    return EXIT_FAILURE;
  }
  
  string url(argv[1]);
  string response;
  string error;

  bool success = Connection::smart_get(url, &response, &error);

  if (!success) {
    cerr << error << endl;
    return EXIT_FAILURE;
  }

  cout << response << endl;
  return EXIT_SUCCESS;
}
