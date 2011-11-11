#include <QtGui>

#include "central-window.h"
#include <iostream>
#include <string>

#include "train-dialog.h"
#include "write-dialog.h"
#include "delete-dialog.h"

int columns = 2;
int rows = 10;

CentralWindow::CentralWindow()
{
  QGridLayout *layout = new QGridLayout;

  beginButton = new QPushButton("Detect Target");
  connect(beginButton, SIGNAL(clicked()), this, SLOT(train()));
  
  layout->addWidget(beginButton, 4, 0, 2, 1);

  writeButton = new QPushButton("Write");
  connect(writeButton, SIGNAL(clicked()), this, SLOT(writePrompt()));

  layout->addWidget(writeButton, 2, 0, 2, 1);

  deleteButton = new QPushButton("Delete");
  connect(deleteButton, SIGNAL(clicked()), this, SLOT(deletePrompt()));

  layout->addWidget(deleteButton, 3, 0, 2, 1);

  listView = new QListView;
  layout->addWidget(listView, 0, 1, 10, 1);

  layout->setColumnStretch(0, 10);
  layout->setColumnStretch(1, 30);


  listModel = new QStandardItemModel();
  listView->setModel(listModel );

  setLayout(layout);
}

void CentralWindow::train() {
  std::cout << "Training." << std::endl;
  TrainDialog dialog;
  dialog.exec();
}

void CentralWindow::addItem(std::string s) {
  QStandardItem *item;
  item = new QStandardItem();

  QVariant variant(s.c_str());
  item->setData(variant, Qt::DisplayRole );
  // item->setData( QImage("images/copy.png"), Qt::DecorationRole );
  item->setEditable( false );   
 
  listModel->appendRow( item );

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
