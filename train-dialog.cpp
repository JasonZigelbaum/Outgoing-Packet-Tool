#include <QtGui>

#include "train-dialog.h"
#include <iostream>
#include "packet-sniffer.h"
#include <pcap/pcap.h>
#include "globals.h"


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

  setWindowTitle(tr("Basic Layouts"));
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
      pcap_breakloop(PacketSniffer::instance()->handle);

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

void train() {
  PacketSniffer::instance()->fill_packet_sieve();
}

void assess() {
  PacketSniffer::instance()->select_packets();
}
