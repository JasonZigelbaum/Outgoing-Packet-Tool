#include <cstdlib>
#include <string>
#include <iostream>
#include "main-window.h"
#include "central-window.h"

#include "route-editor.h"

using namespace std;

bool RouteEditor::addRouteEntry(std::string ip) {
	string cmnd = "route add " + ip + " 127.0.0.1";
	char* c = &cmnd[0];
	if(system(c) == 0) {
		cout << "route" << ip << "successfully added!" << endl;
		return true;
	}
	cout << "route" << ip << "failed to be added." << endl;
	return false;
}

bool RouteEditor::deleteRouteEntry(std::string ip) {
	string cmnd = "route delete " + ip;
	char* c = &cmnd[0];
	if(system(c) == 0) {
		cout << "route" << ip << "successfully deleted!" << endl;
		return true;
	}
	cout << "route" << ip << "failed to be deleted." << endl;
	return false;
}