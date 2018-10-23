#include "Cryption_tool.h"
#include <QtWidgets/QApplication>
#include <QFile>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	Cryption_tool w;
	
	w.show();
	return a.exec();
}
