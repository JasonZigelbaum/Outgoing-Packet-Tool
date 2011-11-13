#ifndef PASSWORD_WINDOW_H
#define PASSWORD_WINDOW_H

#include <QWidget>
#include <QStandardItemModel>
#include <string>

class QTextEdit;
class QLineEdit;
class QLabel;
class QPushButton;
class QListView;
class QListWidget;

void sniff();

class PasswordWindow : public QWidget {
  Q_OBJECT

 public:
  QListWidget* listWidget;
  PasswordWindow();
  public slots:
  void enable();
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
