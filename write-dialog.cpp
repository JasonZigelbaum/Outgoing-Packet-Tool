#include <QtGui>

#include <string>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include "globals.h"
#include "write-dialog.h"

using namespace std;

WriteDialog::WriteDialog() {
  bool ok;
  QString txt = QInputDialog::getText(this, tr("Write to /etc/hosts"),tr("Record to add:"), QLineEdit::Normal, "ip dns-record", &ok);
  std::string record = txt.toUtf8().constData();
  if(ok && record != "ip dns-record" && !txt.isEmpty()) {
	writeRecord(record);
  }
}

void WriteDialog::writeRecord(std::string record) {
  ofstream outdata; // outdata is like cin
  outdata.open(HOSTS_FILE.c_str(), ios::app); // opens the file in append mode
  if( !outdata ) { // file couldn't be opened
     cerr << "Error: file could not be opened" << endl;
  }
  
  outdata << record << endl;
  outdata.close();
}