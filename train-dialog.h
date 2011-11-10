#ifndef TRAIN_DIALOG_H
#define TRAIN_DIALOG_H

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

class TrainDialog : public QDialog
{
  Q_OBJECT

    public:
  TrainDialog();
  public slots:
  void beginTraining();
  void timerFired();
  void handleFinished();
  void doneAssessing();

 private:

  QVBoxLayout* layout;
  QLabel* trainLabel;
  QPushButton* continueButton;
  QPushButton* trainButton;
  QProgressBar* progressBar;
  QTimer* timer;

  QFutureWatcher<void> watcher;
  QFuture<void> future;

};

#endif
