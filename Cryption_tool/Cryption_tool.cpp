#include "Cryption_tool.h"
#include <QFile>
Cryption_tool::Cryption_tool(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	QFile qss(":/Cryption_tool/test.qss");//��Դ·��
	qss.open(QFile::ReadOnly);
	this->setStyleSheet(qss.readAll());
	qss.close();
}
