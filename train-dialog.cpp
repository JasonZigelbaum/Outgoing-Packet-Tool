#include <QtGui>

#include "train-dialog.h"
#include <iostream>
#include "packet-sniffer.h"
#include <pcap/pcap.h>
#include "globals.h"
#include <sstream>
#include "main-window.h"
#include "central-window.h"


const int TRAIN_TIME_S = 5;

TrainDialog::TrainDialog()
{
  layout = new QVBoxLayout;

  trainLabel = new QLabel("Close target application and then click below to begin training.\nThis process will help us identify communication by the target application.");
  trainButton = new QPushButton("Train");
  layout->addWidget(trainLabel);
  layout->addWidget(trainButton);
  connect(trainButton, SIGNAL(clicked()), this, SLOT(beginTraining()));
  setLayout(layout);

  setWindowTitle(tr("Detect Target"));
}

void TrainDialog::beginTraining() {
  progressBar = new QProgressBar();
  progressBar->setMaximum(TRAIN_TIME_S);
  trainButton->setVisible(false);
  layout->removeWidget(trainButton);
  layout->addWidget(progressBar);
  timer = new QTimer(this);
  connect(timer, SIGNAL(timeout()), this, SLOT(timerFired()));
  timer->start(1000);

  connect(&watcher, SIGNAL(finished()), this, SLOT(handleFinished()));
  QFuture<void> future = QtConcurrent::run(train);
  watcher.setFuture(future);
}

void TrainDialog::timerFired() {
  progressBar->setValue(progressBar->value() + 1);
  std::cout << "Ticking: " << progressBar->value();
  if (progressBar->value() == TRAIN_TIME_S) {
    pcap_breakloop(PacketSniffer::instance()->handle);
  }
}

void TrainDialog::doneAssessing() {
  std::cout << "done assessing fire" << std::endl;
  pcap_breakloop(PacketSniffer::instance()->handle);
  continueButton->setVisible(false);
  layout->removeWidget(continueButton);
  trainLabel->setText("Loading suspect hosts...");
  trainLabel->update();
  trainLabel->repaint();
  connect(&watcher, SIGNAL(finished()), this, SLOT(doneAddingToList()));
  QFuture<void> future = QtConcurrent::run(addToList);
  watcher.setFuture(future);
}

void TrainDialog::doneAddingToList() {
  done(0);
}


void TrainDialog::handleFinished() {
  std::cout << "Thread finished." << std::endl;
  timer->stop();
  trainLabel->setText("Now turn on the target application and wait until it attempts\nauthentication.  Hit the button below when this step is completed.");
  progressBar->setVisible(false);
  layout->removeWidget(progressBar);
  continueButton = new QPushButton("Continue");
  connect(continueButton, SIGNAL(clicked()), this, SLOT(doneAssessing()));
  layout->addWidget(continueButton);
  QFuture<void> future = QtConcurrent::run(assess);
}

void addToList() {
  AddressMap::iterator iter;
  PacketSieve* sieve = PacketSniffer::instance()->sieve;
  std::cout << "Thread: " << std::endl;
  for (iter = sieve->suspect_hosts_.begin();
       iter != sieve->suspect_hosts_.end(); ++iter) {
    stringstream stream;
    stream << sieve->reverse_dns(iter->first) << " (" << iter->first << ")";
    std::cout << iter->first << " " << sieve->reverse_dns(iter->first)
              << " " << iter->second << std::endl;
    MainWindow::instance()->centralWindow->addItem(stream.str());
  }
}

void train() {
  PacketSniffer::instance()->fill_packet_sieve();
}

// Should probably have a "get candidates method" to put candidates into a unique QT widget for writing to the hosts file...

void assess() {
  std::cout << "Assessing." << std::endl;
  PacketSniffer::instance()->select_packets();
}
