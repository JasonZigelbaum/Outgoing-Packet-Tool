#include <QtGui>

#include "central-window.h"
#include <iostream>
#include <string>
#include <sstream>

#include "train-dialog.h"
#include "write-dialog.h"
#include "delete-dialog.h"
#include "attack-dialog.h"

int columns = 2;
int rows = 10;

CentralWindow::CentralWindow()
{
  QGridLayout *layout = new QGridLayout;

  beginButton = new QPushButton("Detect Target");
  connect(beginButton, SIGNAL(clicked()), this, SLOT(train()));
  
  layout->addWidget(beginButton, 4, 0, 2, 1);

  beginButton = new QPushButton("Attack Selected");
  connect(beginButton, SIGNAL(clicked()), this, SLOT(attack()));
  
  layout->addWidget(beginButton, 5, 0, 2, 1);


  // writeButton = new QPushButton("Write");
  // connect(writeButton, SIGNAL(clicked()), this, SLOT(writePrompt()));

  // layout->addWidget(writeButton, 2, 0, 2, 1);

  // deleteButton = new QPushButton("Delete");
  // connect(deleteButton, SIGNAL(clicked()), this, SLOT(deletePrompt()));

  // layout->addWidget(deleteButton, 3, 0, 2, 1);

  listWidget = new QListWidget;
  listWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
  layout->addWidget(listWidget, 0, 1, 10, 1);
  // for (int i = 0; i < 5; ++i) {
  //   std::stringstream s;
  //   s << "hostname (148.222.1." << i << ")";
  //   listWidget->addItem(s.str().c_str());
  // }

  layout->setColumnStretch(0, 10);
  layout->setColumnStretch(1, 30);

  setLayout(layout);
}

void CentralWindow::train() {
  TrainDialog dialog;
  dialog.exec();
}

void CentralWindow::attack() {
  AttackDialog dialog;
  dialog.exec();
}


void CentralWindow::writePrompt() {
  std::cout << "Writing" << std::endl;
  WriteDialog write_d;
  write_d.exec();
}

void CentralWindow::deletePrompt() {
  std::cout << "Deleting" << std::endl;
  DeleteDialog delete_d;
  delete_d.exec();
}
