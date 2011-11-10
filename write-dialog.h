#ifndef WRITE_DIALOG_H
#define WRITE_DIALOG_H

#include <QtGui>

#include <string>
#include <vector>

class QAction;
class QDialogButtonBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QMenu;
class QMenuBar;
class QPushButton;
class QTextEdit;
class QProgressBar;

class WriteDialog : public QDialog 
{
  Q_OBJECT

// Create a QT Dialogue- Have it take in the string to add, and add it.

public:
  WriteDialog();
  public slots:
  void writeRecord(std::string record);

private:
};


#endif
