#ifndef DELETE_DIALOG_H
#define DELETE_DIALOG_H

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

class DeleteDialog : public QDialog 
{
  Q_OBJECT

// Create a QT Dialogue- Have it take in the string to add, and add it.

public:
  DeleteDialog();
  public slots:
  void deleteRecord(std::string record);

private:
};


#endif
