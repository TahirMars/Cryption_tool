#pragma once
#include <QtWidgets/QMainWindow>
#include "ui_Cryption_tool.h"
#include <string>

class Cryption_tool : public QMainWindow
{
	Q_OBJECT

public:
	Cryption_tool(QWidget *parent = Q_NULLPTR);

private:
	Ui::Cryption_toolClass ui;

private slots:
	void encryption();
	void decryption();

};
