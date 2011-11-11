#include <QtGui>

#include "attack-dialog.h"
#include <iostream>
#include <fstream>
#include "packet-sniffer.h"
#include <pcap/pcap.h>
#include "globals.h"
#include <sstream>
#include "main-window.h"
#include "central-window.h"
#include "route-editor.h"

AttackDialog::AttackDialog()
{
  layout = new QGridLayout;
  comboBox = new QComboBox();
  comboBox->addItem("Connection Denial");
  comboBox->addItem("Attack 2");
  comboBox->addItem("Attack 3");
  connect(comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(indexChanged(int)));

  attackTypeLabel = new QLabel("Attack type:");

  layout->addWidget(attackTypeLabel, 0, 0, 2, 4);
  layout->addWidget(comboBox, 0, 4, 2, 4);

  hostFileBox = new QCheckBox("Edit host file");
  routingBox = new QCheckBox("Edit routing table");
  indexChanged(0);

  // indexList = MainWindow::instance()->centralWindow->
  //   listView->selectedIndexes();
  // QModelIndex index; 
  // for(int i = 0; i < indexList.size(); ++i) {
  //   index = indexList.at(i);
  //   //std::cout << "Selected: " << index.data().toString() << std::endl;
  // }
  // trainLabel = new QLabel("Close target application and then click below to begin training.\nThis process will help us identify communication by the target application.");

  attackButton = new QPushButton("Attack");
  layout->addWidget(attackButton, 10, 4, 2, 4);
  connect(attackButton, SIGNAL(clicked()), this, SLOT(attack()));


  setLayout(layout);

  setWindowTitle(tr("Attack"));
}

void AttackDialog::indexChanged(int index) {
  layout->removeWidget(hostFileBox);
  layout->removeWidget(routingBox);
  hostFileBox->setVisible(false);
  routingBox->setVisible(false);

  // Stop communication
  if (index == 0) {
    layout->addWidget(hostFileBox, 4, 0, 2, 4);
    layout->addWidget(routingBox, 4, 4, 2, 4);
    hostFileBox->setVisible(true);
    routingBox->setVisible(true);
  }
}

void AttackDialog::attack() {
  foreach(QListWidgetItem *selectedItem, MainWindow::instance()->centralWindow->listWidget->selectedItems()) {
    std::string item_string = selectedItem->data(0).toString().toStdString();
    selectedItem->setData(Qt::ForegroundRole, QColor(Qt::red));
    int i = 0;
    int start;
    while(item_string[i] != '(') ++i;
    start = i + 1;
    string ip = item_string.substr(start, item_string.length() - start - 1);
    string host = item_string.substr(0, start - 1);
    // Attack ip_address depending on attack selected.
    if (comboBox->currentIndex() == 0) {
      // Put calls to host file and routing changes here.
      std::cout << "Connection prevention attacking: " << ip << std::endl;
      if(hostFileBox->checkState() == Qt::Checked) {
	std::cout << "here: " << host << std::endl;
	  std::ofstream outdata; // outdata is like cin
	  outdata.open(HOSTS_FILE.c_str(), ios::app); // opens the file in append mode
	  if( !outdata ) { // file couldn't be opened
	    cerr << "Error: file could not be opened" << endl;
            return;
	  }
  
	  outdata << "127.0.0.1      " << host << std::endl;
	  outdata.close();
      }
      if(routingBox->checkState() == Qt::Checked) {
        RouteEditor editor;
        editor.addRouteEntry(ip);
      }
    }

  }
  close();
}

