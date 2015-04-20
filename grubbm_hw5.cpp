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

using namespace std;

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
      error->assign("not implemented");
      return false;
    }

    // Close the connection.
    virtual bool close(string *error) {
      error->assign("not implemented");
      return false;
    }

  protected:
    // Send packet over the connection.
    virtual bool send(const string &packet, string *error) {
      error->assign("not implemented");
      return false;
    }

    // Receive packet over the connection.
    virtual bool recv(string *packet, string *error) {
      error->assign("not implemented");
      return false;
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
    static bool parse_url(
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
  private:
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
  private:
};

bool Connection::parse_url(
    const string &url,
    string *host,
    string *port,
    string *path,
    string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool Connection::construct_request(
    const string &host,
    const string &port,
    const string &path,
    string *request,
    string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
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

  if (!connect(host, port, error)) {
    return false;
  }

  string request;
  if (!construct_request(host, port, path, &request, error)) {
    return false;
  }

  if (!send(request, error)) {
    return false;
  }

  if (!recv(response, error)) {
    return false;
  }

  return true;
}

bool HttpsConnection::connect(
    const string &host,
    const string &port,
    string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpsConnection::close(string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpsConnection::send(const string &packet, string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpsConnection::recv(string *packet, string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpConnection::connect(
    const string &host,
    const string &port,
    string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpConnection::close(string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpConnection::send(const string &packet, string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

bool HttpConnection::recv(string *packet, string *error) {
  // TODO
  error->assign("not yet implemented");
  return false;
}

Connection *Connection::make_connection(const string &url) {
  if (url.substr(0, 5) == "https") {
    return new HttpsConnection();
  } else {
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





/****************************************************
 ****************************************************
 **********    THE OLD CODE LIES BELOW    ***********
 ****************************************************
 ****************************************************/





/* This function handles the parsing of the url argument into
   host, port, and path and stores those values in a map that 
   is passed in. It also determines whether to use http or https  */
void parse_url(string url, map<string,string> &url_info) {
  bool port_included = false;
  string port = "";
  string host = "";
  string path = "";
  string is_https_value = "";
  int count = 7;
  
  // parse host from url
  while (count != url.size()) {
    if (url[count] == 's') {
      is_https_value = "yes";
      url_info["is_https"] = is_https_value;
    }
    if (url[count] == ':') {
      count++;
      port_included = true;
      break;
    }
    else if (url[count] == '/') {
      break;
    }
    else {
      host += url[count];
      count++;
    }
  }

  // parse port from url
  while (port_included && count != url.size()) {
    if (url[count] == '/') {
      break;
    }
    port += url[count];
    count++;
  }

  // parse path from url
  while (count != url.size()) {
    path += url[count]; 
    count++;
  }

  // if port not included, make it default 
  if (!port_included) {
    auto itr = url_info.find("is_https");
    // if not given an https url, default is 80
    if (itr == url_info.end()) {
      is_https_value = "no";
      url_info["is_https"] = is_https_value;
      port = "80";
    }
    // if is https, default is 443
    else {
      port = "443";
    }
  } 

  // add values to map
  url_info["host"] = host;
  url_info["port"] = port;
  url_info["path"] = path;
}

/* This function sends all data, even if it doesn't all go at once */
int send_all(int fd, const void *data, size_t size, int flags) {
  ssize_t ret, sent = 0;
  uint8_t *bytes = (uint8_t *)data;
  
  while (size > 0) {
    ret = send(fd, bytes, size, flags);

    if (ret < 0) {
      return ret;
    }
    size -= ret;
    bytes += ret;
    sent += ret;
  }
  return sent;
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

/* MAIN */
int old_main(int argc, char *argv []) {
  int sockfd, ret, request_length;
  struct addrinfo ai_hints;
  struct addrinfo *ai_results, *j;
  map<string,string> url_info;
  char recvbuf[80];
  
  // ensure program is given correct number of arguments
  if (argc != 2) {
    cerr << "Wrong Number of Arguments! Please supply a URL" << endl; 
    return EXIT_FAILURE;
  }
  
  // parse the argument into host, port, and path, and put into the map
  parse_url(string(argv[1]), url_info);
  string host = url_info["host"];
  string port = url_info["port"];
  string path = url_info["path"];
  bool is_https = false;
  
  // check whether it is https or http
  if (url_info["is_https"] == "yes") {
    is_https = true;
  }

  // create an IPV6 Socket
  sockfd = socket(AF_INET6, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("socket");
    return EXIT_FAILURE;
  } 

  // find addresses from map
  memset(&ai_hints, 0, sizeof(ai_hints));
  ai_hints.ai_family = AF_INET6;
  ai_hints.ai_socktype = SOCK_STREAM;
  ai_hints.ai_flags = AI_ALL | AI_V4MAPPED | AI_ADDRCONFIG;

  ret = getaddrinfo(host.c_str(), port.c_str(), &ai_hints, &ai_results);
  if (ret != 0) {
    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(ret));
    return EXIT_FAILURE;
  } 

  // Loop through the addresses and try to connect() to each until one that works is found.
  bool success = false;
  for (j = ai_results; j != NULL; j = j->ai_next) {
    ret = connect(sockfd, j->ai_addr, j->ai_addrlen);
    if (ret == 0) {
      success = true; // a connection has successfully been made!
      break;
    }
  } 

  // clean up ai_results
  freeaddrinfo(ai_results);

  // if connection isn't successful, error out of program
  if (!success) {
    perror("connect");
    return EXIT_FAILURE;
  }

  // send request
  string request = "GET " + path + " HTTP/1.1\r\n";
  string headers = "Host: " + host + ":" + port+ "\r\nUser-Agent: grubbm_hw3/1.0\r\n\r\n";
  string send_this = request + headers;
  ret = send_all(sockfd, send_this.c_str(), send_this.size(), 0);
  if (ret < 0) {
    perror("send_all");
    return EXIT_FAILURE;
  } 

  string backlog = "";
  int content_length = -1;
  const string pattern = "Content-Length: ";
  // first get headers, line-by-line
  while (true) {
    string line, new_backlog;
    get_line(sockfd, backlog, line, new_backlog);
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
    cerr << "Content-Length not provided in response!" << endl;
    return EXIT_FAILURE;
  }
  // print out blank line to separate headers (in stderr) from body (in stdout)
  cout << endl; 

  // now print out backlog
  cout << backlog;

  // now it is known exactly how much is left to receive, receive it in body_buf
  int remaining_to_recv = content_length - backlog.size() + 1;
  char body_buf[remaining_to_recv];

  while (remaining_to_recv > 0) {
    ret = recv(sockfd, body_buf, remaining_to_recv, 0);
    if (ret < 0) {
      perror("recv");
      return EXIT_FAILURE;
    }
    if (ret == 0) {
      break;
    }
    // print out body to stdout
    fwrite(body_buf, sizeof(char), ret, stdout);
    remaining_to_recv -= ret;
  }

  // close socket
  close(sockfd);  

  return EXIT_SUCCESS; 
}
