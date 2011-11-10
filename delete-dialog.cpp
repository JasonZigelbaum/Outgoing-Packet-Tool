#include <QtGui>

#include <string>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include "globals.h"
#include "delete-dialog.h"

using namespace std;

DeleteDialog::DeleteDialog() {
  bool ok;
  QString txt = QInputDialog::getText(this, tr("Delete at /etc/hosts"),tr("Record to Delete:"), QLineEdit::Normal, "ip dns-record", &ok);
  std::string record = txt.toUtf8().constData();
  if(ok && record != "ip dns-record" && !txt.isEmpty()) {
	deleteRecord(record);
  }
}

void DeleteDialog::deleteRecord(std::string record) {
  vector<string> file;
  string temp;

  ifstream infile(HOSTS_FILE.c_str());

  while( !infile.eof() )
  {
    getline(infile, temp);
    file.push_back(temp);
  }
  // done reading file
  infile.close();

  string item = record;

  for(int i = 0; i < (int)file.size(); ++i)
  {
    if(file[i].substr(0, item.length()) == item)
    {
        file.erase(file.begin() + i);
        cout << record << " erased!" << endl;
        i = 0; // Reset search
    }
  }

  //write new order list back out
  ofstream out(HOSTS_FILE.c_str(), ios::out | ios::trunc);
  
  for(vector<string>::const_iterator i = file.begin(); i != file.end(); ++i)
  {
    out << *i << endl;
  }
  out.close();
}