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
class QListWidget;


class CentralWindow : public QWidget {
  Q_OBJECT

 public:
  QListWidget* listWidget;
  CentralWindow();
  public slots:
  void train();
  void attack();
  void writePrompt();
  void deletePrompt();

 private:
  QPushButton* beginButton;
  QPushButton* trainButton;
  QPushButton* writeButton;
  QPushButton* deleteButton;
  QPushButton* attackButton;





};

#endif
