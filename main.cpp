#include "processenjoyer.h"
#include <QtWidgets/QApplication>
#include <QStringConverter>
#include "backend.h" // 

int main(int argc, char *argv[]){
    // mbks2 lab
    QApplication a(argc, argv);
    QIcon icon("C:\\icon.ico");
    a.setWindowIcon(icon);
    processenjoyer w;
    w.show();
    return a.exec();
}
