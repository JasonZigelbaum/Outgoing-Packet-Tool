#include <QtGui>

#include "main-window.h"
#include "central-window.h"
#include "password-window.h"

// Using singleton design pattern.
MainWindow* MainWindow::instance_ = NULL;

MainWindow* MainWindow::instance() {
   if (instance_ == NULL) {
      instance_ = new MainWindow();
   }
   return instance_;
}

MainWindow::MainWindow()
{
  centralWindow = new CentralWindow(); 
  passwordWindow = new PasswordWindow();
  tabWidget = new QTabWidget();
  tabWidget->addTab(centralWindow, "Software Authentication");
  tabWidget->addTab(passwordWindow, "Password Sniffing");
  setCentralWidget(tabWidget);

  createActions();
  createMenus();
  //createToolBars();
  createStatusBar();

  setUnifiedTitleAndToolBarOnMac(true);
  setMinimumHeight(450);
  setMinimumWidth(800);
}


void MainWindow::closeEvent(QCloseEvent *event)
{
    event->accept();
}


void MainWindow::about()
{
  QMessageBox::about(this, tr("About"),
		     tr("This application is a project by Jonathan Wald and Jason Zigelbaum for Network Security (CSE571) at Washington University in St. Louis."));
}

void MainWindow::createActions()
{

  exitAct = new QAction(tr("E&xit"), this);
  exitAct->setShortcuts(QKeySequence::Quit);
  exitAct->setStatusTip(tr("Exit the application"));
  connect(exitAct, SIGNAL(triggered()), this, SLOT(close()));


  aboutAct = new QAction(tr("&About"), this);
  aboutAct->setStatusTip(tr("Show the application's About box"));
  connect(aboutAct, SIGNAL(triggered()), this, SLOT(about()));

}

void MainWindow::createMenus()
{
  fileMenu = menuBar()->addMenu(tr("&File"));
  fileMenu->addSeparator();
  fileMenu->addAction(exitAct);


  menuBar()->addSeparator();

  helpMenu = menuBar()->addMenu(tr("&Help"));
  helpMenu->addAction(aboutAct);
}



void MainWindow::createStatusBar()
{
  statusBar()->showMessage(tr("Ready"));
}

