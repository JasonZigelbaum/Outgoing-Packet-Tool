#include <QtGui>

#include "central-window.h"
#include <iostream>

#include "functions.h"
#include "train-dialog.h"

int columns = 2;
int rows = 10;

CentralWindow::CentralWindow()
{
  QGridLayout *layout = new QGridLayout;

  // for (int i = 0; i < 3; ++i) {
  //   labels[i] = new QLabel(tr("Line %1:").arg(i + 1));
  //   lineEdits[i] = new QLineEdit;
  //   layout->addWidget(labels[i], i + 1, 0);
  //   layout->addWidget(lineEdits[i], i + 1, 1);
  // }
  beginButton = new QPushButton("Begin Crack");
  connect(beginButton, SIGNAL(clicked()), this, SLOT(train()));

  layout->addWidget(beginButton, 4, 0, 2, 1);

  smallEditor = new QTextEdit;
  smallEditor->setPlainText(tr("This widget takes up about two thirds of the "
			       "grid layout."));
  layout->addWidget(smallEditor, 0, 1, 10, 1);

  layout->setColumnStretch(0, 10);
  layout->setColumnStretch(1, 30);
  setLayout(layout);
}

void CentralWindow::train() {
  std::cout << "Training." << std::endl;
  TrainDialog dialog;
  dialog.exec();
}
