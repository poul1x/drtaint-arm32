/*
  example main.cpp for picohttpclient.hpp ... generic, lightweight HTTP 1.1 client
  see picohttpclient.hpp for details
*/

#include <iostream>
#include <map>
#include <string>
#include "picohttpclient.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  if(argc == 1) {
    cout << "Use " << argv[0] << " http://example.org" << endl;
    return 1;
  }

  // HTTPResponse response = HTTPClient::request(HTTPClient::GET, URI(argv[1]));
  HTTPResponse response = HTTPClient::request(HTTPClient::GET, URI(argv[1]));

  if(!response.success) {
    cout << "Request failed!" << endl;
    return -1;
  }

  cerr << "Request success" << endl;

  cerr << "Server protocol: " << response.protocol << endl;
  cerr << "Response code: " << response.response << endl;
  cerr << "Response string: " << response.responseString << endl;

  cerr << "Headers:" << endl;

  for(stringMap::iterator it = response.header.begin(); it != response.header.end(); it++) {
    cerr << "\t" << it->first << "=" << it->second << endl;
  }

  cout << response.body << endl;

  return 0;
}
