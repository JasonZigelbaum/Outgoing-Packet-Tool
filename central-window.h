#ifndef CENTRAL_WINDOW_H
#define CENTRAL_WINDOW_H

#include <QWidget>

class QTextEdit;
class QLineEdit;
class QLabel;
class QPushButton;

//const int NumGridRows = 3;

class CentralWindow : public QWidget {
  Q_OBJECT

 public:
  CentralWindow();
  public slots:
  void train();

 private:
  QPushButton* beginButton;
  QPushButton* trainButton;
  QTextEdit *smallEditor;
  QTextEdit *bigEditor;
  QLabel *labels[3];
  QLineEdit *lineEdits[3];


};

#endif
