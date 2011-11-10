#include <QtGui>

#include "central-window.h"
#include <iostream>
#include <string>

#include "train-dialog.h"

int columns = 2;
int rows = 10;

CentralWindow::CentralWindow()
{
  QGridLayout *layout = new QGridLayout;

  beginButton = new QPushButton("Begin Crack");
  connect(beginButton, SIGNAL(clicked()), this, SLOT(train()));

  layout->addWidget(beginButton, 4, 0, 2, 1);

  listView = new QListView;
  layout->addWidget(listView, 0, 1, 10, 1);

  layout->setColumnStretch(0, 10);
  layout->setColumnStretch(1, 30);


  listModel = new QStandardItemModel();
  listView->setModel(listModel );
  addItem("what upp");

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
  item->setData( QImage("images/copy.png"), Qt::DecorationRole );
  item->setEditable( false );   
 
  listModel->appendRow( item );

}
