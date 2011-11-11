#include <QApplication>

#include "main-window.h"

int main(int argc, char *argv[])
{
  Q_INIT_RESOURCE(application);

  QApplication app(argc, argv);
  app.setOrganizationName("C0ntag10n");
  app.setApplicationName("Software Authentication Cracker");
  //specify a  new font.
  QFont newFont("Impact", 12, QFont::Bold);
  //set font of application
  QApplication::setFont(newFont);
  QApplication::setQuitOnLastWindowClosed(false);
  MainWindow::instance()->show();
  return app.exec();
}
