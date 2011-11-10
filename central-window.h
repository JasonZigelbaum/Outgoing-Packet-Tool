#ifndef CENTRAL_WINDOW_H
#define CENTRAL_WINDOW_H

#include <QWidget>
#include <QStandardItemModel>
#include <string>

class QTextEdit;
class QLineEdit;
class QLabel;
class QPushButton;
class QListView;

//const int NumGridRows = 3;

class CentralWindow : public QWidget {
  Q_OBJECT

 public:
  CentralWindow();
  public slots:
  void train();
  void writePrompt();
  void deletePrompt();
  void addItem(std::string s);

 private:
  QPushButton* beginButton;
  QPushButton* trainButton;
  QPushButton* writeButton;
  QPushButton* deleteButton;
  QListView* listView;
  QStandardItemModel * listModel;



};

#endif
