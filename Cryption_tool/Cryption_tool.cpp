#include "Cryption_tool.h"
#include <QFile>
#include <QMessageBox>
#include "DES.h"
#include <string.h>

Cryption_tool::Cryption_tool(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	connect(this, SIGNAL(on_pushbutton_clicked()), SLOT(encryption()));
	QFile qss(":/Cryption_tool/test.qss");//��Դ·��
	qss.open(QFile::ReadOnly);
	this->setStyleSheet(qss.readAll());
	qss.close();
}
/**
*  ���뺯��f������32λ���룬48λ����Կ������һ��32λ�����
*/

bitset<32> f(bitset<32> R, bitset<48> K) {
	bitset<48> expandR;//��չ���R 
					   //1.λѡ����E����32λ��R��չΪ48λ
	for (int i = 0; i<48; ++i) {//��˻���洢����� 
		expandR[47 - i] = R[32 - E[i]];
	}
	//2.��չ���R������ԿK���а�λ��ģ2������ 
	expandR = expandR ^ K;
	//3.���ң�S_BOX�������û�
	int x = 0;
	bitset<32> output;
	for (int i = 0; i<48; i = i + 6) {
		int row = expandR[47 - i] * 2 + expandR[47 - i - 5];
		int col = expandR[47 - i - 1] * 8 + expandR[47 - i - 2] * 4 + expandR[47 - i - 3] * 2 + expandR[47 - i - 4];
		int num = S_BOX[i / 6][row][col];
		bitset<4> binary(num);
		output[31 - x] = binary[3];
		output[31 - x - 1] = binary[2];
		output[31 - x - 2] = binary[1];
		output[31 - x - 3] = binary[0];
		x += 4;
	}
	//4.output�����û�����P
	bitset<32> temp = output;
	for (int i = 0; i<32; i++)
		output[31 - i] = temp[32 - P[i]];
	return output;
}

/**
*  ��56λ��Կ��ǰ�󲿷ֽ�������
*/
bitset<28> leftShift(bitset<28> k, int shift) {
	bitset<28> tmp = k;
	for (int i = 27; i >= 0; --i)
	{
		if (i - shift<0)
			k[i] = tmp[i - shift + 28];
		else
			k[i] = tmp[i - shift];//Ϊ��ʵ��ѭ���������λΪ ��ȷֵ 
	}

	return k;
}

/*
*  ����16��48λ������Կ
*/
void generateKeys() {
	bitset<56> Key;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;
	//ȥ��8λ����ż�ԣ���64λ��Կ��Ϊ56λ
	for (int i = 0; i<56; i++)
		Key[55 - i] = key[64 - PC_1[i]];
	//��������Կ��������subKey[16]�� 
	for (int round = 0; round<16; round++) {
		for (int i = 28; i<56; i++)//��˻�ʵ����ǰ28λ���ڴ洢���Ǻ�28λ 
			left[i - 28] = Key[i];
		for (int i = 0; i<28; i++)
			right[i] = Key[i];
		//����
		left = leftShift(left, shiftBits[round]);
		right = leftShift(right, shiftBits[round]);
		for (int i = 28; i<56; i++)
			Key[i] = left[i - 28];
		for (int i = 0; i<28; i++)
			Key[i] = right[i];
		for (int i = 0; i<48; i++)
			compressKey[47 - i] = Key[56 - PC_2[i]];
		subKey[round] = compressKey;
	}
}

/**
*  ��char�ַ�תΪ������
*/
bitset<64> charToBitset(const char s[8]) {
	bitset<64> bits;
	for (int i = 0; i<8; i++)
		for (int j = 0; j<8; ++j)
			bits[i * 8 + j] = ((s[i] >> j) & 1);
	return bits;
}



/**
* DES����
*/
bitset<64> encrypt(bitset<64> &plain) {
	bitset<64> cipher;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	//1.��ʼ�û�IP
	for (int i = 0; i<64; i++)
		currentBits[63 - i] = plain[64 - IP[i]];
	//2.��ȡLi��Ri 
	for (int i = 32; i<64; i++)
		left[i - 32] = currentBits[i];
	for (int i = 0; i<32; i++)
		right[i] = currentBits[i];
	// 3.��16�ֵ���	
	for (int round = 0; round<16; round++) {
		newLeft = right;
		right = left ^ f(right, subKey[round]);
		left = newLeft;
	}
	//4.�ϲ�L16��R16��ע��ϲ�Ϊ R16L16	
	for (int i = 0; i<32; i++)
		cipher[i] = left[i];
	for (int i = 32; i<64; i++)
		cipher[i] = right[i - 32];
	//5.��β�û�IP-1	
	currentBits = cipher;
	for (int i = 0; i<64; i++)
		cipher[63 - i] = currentBits[64 - IP_1[i]];
	//��������	
	return cipher;
}

/**
*  DES����
*/
bitset<64> decrypt(bitset<64>& cipher) {
	bitset<64> plain;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	// ��һ������ʼ�û�IP	
	for (int i = 0; i<64; i++)
		currentBits[63 - i] = cipher[64 - IP[i]];
	// �ڶ�������ȡ Li �� Ri	
	for (int i = 32; i<64; i++)
		left[i - 32] = currentBits[i];
	for (int i = 0; i<32; i++)
		right[i] = currentBits[i];
	// ����������16�ֵ���������Կ����Ӧ�ã�	
	for (int round = 0; round<16; round++) {
		newLeft = right;
		right = left ^ f(right, subKey[15 - round]);
		left = newLeft;
	}
	// ���Ĳ����ϲ�L16��R16��ע��ϲ�Ϊ R16L16	
	for (int i = 0; i<32; i++)
		plain[i] = left[i];
	for (int i = 32; i<64; i++)
		plain[i] = right[i - 32];
	// ���岽����β�û�IP-1	
	currentBits = plain;
	for (int i = 0; i<64; i++)
		plain[63 - i] = currentBits[64 - IP_1[i]];
	// ��������	
	return plain;
}

void Cryption_tool::encryption() {
	string k = ui.lineEdit_6->text().toStdString();
	string m = ui.textEdit->toPlainText().toStdString();
	bitset<64> plain = charToBitset(m.c_str());
	key = charToBitset(k.c_str());
	// ����16������Կ	               
	generateKeys();
	// ����д�� a.txt
	bitset<64> cipher = encrypt(plain);
	fstream file1;
	file1.open("./����.txt", ios::binary | ios::out);
	file1.write((char*)&cipher, sizeof(cipher));
	file1.close();
	ui.textEdit_2->setText((char*)&cipher);
	// ���ļ� a.txt	
	bitset<64> temp;
	file1.open("./����.txt", ios::binary | ios::in);
	file1.read((char*)&temp, sizeof(temp));
	file1.close();
	// ���ܣ���д���ļ� b.txt	
	bitset<64> temp_plain = decrypt(temp);
	file1.open("./����.txt", ios::binary | ios::out);
	file1.write((char*)&temp_plain, sizeof(temp_plain));
	file1.close();

}
void Cryption_tool::decryption() {
	string k = ui.lineEdit_6->text().toStdString();
	string m = ui.textEdit_2->toPlainText().toStdString();
	bitset<64> plain = charToBitset(m.c_str());
	key = charToBitset(k.c_str());
	// ����16������Կ	               
	generateKeys();
	// ����д�� a.txt
	bitset<64> mingwen = decrypt(plain);
	ui.textEdit->setText((char*)&mingwen);
}