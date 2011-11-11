#ifndef ATTACK_DIALOG_H
#define ATTACK_DIALOG_H

#include <QtGui>

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

void train();
void assess();
void addToList();

class AttackDialog : public QDialog
{
  Q_OBJECT

 public:
  AttackDialog();
  public slots:
  void attack();
  void indexChanged(int index);

  
 private:
  QCheckBox* hostFileBox;
  QCheckBox* routingBox;
  QLabel* attackTypeLabel;
  QComboBox* comboBox;

  QGridLayout* layout;
  QPushButton* attackButton;
  
};

#endif
