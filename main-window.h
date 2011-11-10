#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui>

class QAction;
class QMenu;
class QPlainTextEdit;
class CentralWindow;

class MainWindow : public QMainWindow
{
  Q_OBJECT

    public:
  MainWindow();

 protected:
  void closeEvent(QCloseEvent *event);

  private slots:

  void about();

 private:
  void createActions();
  void createMenus();
  void createStatusBar();
  
  QString strippedName(const QString &fullFileName);

  QPlainTextEdit *textEdit;
  QString curFile;

  CentralWindow *centralWindow;

  QMenu *fileMenu;
  QMenu *editMenu;
  QMenu *helpMenu;
  QToolBar *fileToolBar;
  QToolBar *editToolBar;
  QAction *newAct;
  QAction *openAct;
  QAction *saveAct;
  QAction *saveAsAct;
  QAction *exitAct;
  QAction *cutAct;
  QAction *copyAct;
  QAction *pasteAct;
  QAction *aboutAct;
  QAction *aboutQtAct;
};

#endif
