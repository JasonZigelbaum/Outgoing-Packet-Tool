#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui>

class PasswordWindow;
class QAction;
class QMenu;
class QPlainTextEdit;
class CentralWindow;

class MainWindow : public QMainWindow
{
  Q_OBJECT

    public:
  MainWindow();
  static MainWindow* instance();
  CentralWindow *centralWindow;
  PasswordWindow* passwordWindow;
  QTabWidget* tabWidget;

 protected:
  void closeEvent(QCloseEvent *event);

  private slots:

  void about();

 private:
  static MainWindow* instance_;
  void createActions();
  void createMenus();
  void createStatusBar();
  
  QMenu *fileMenu;
  QMenu *helpMenu;
  QAction *exitAct;
  QAction *aboutAct;

};

#endif
