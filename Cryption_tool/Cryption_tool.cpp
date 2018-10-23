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
	QFile qss(":/Cryption_tool/test.qss");//资源路径
	qss.open(QFile::ReadOnly);
	this->setStyleSheet(qss.readAll());
	qss.close();
}
/**
*  密码函数f，接受32位输入，48位子密钥，产生一个32位的输出
*/

bitset<32> f(bitset<32> R, bitset<48> K) {
	bitset<48> expandR;//扩展后的R 
					   //1.位选择函数E，将32位的R扩展为48位
	for (int i = 0; i<48; ++i) {//大端机里存储倒序的 
		expandR[47 - i] = R[32 - E[i]];
	}
	//2.扩展后的R与子密钥K进行按位的模2加运算 
	expandR = expandR ^ K;
	//3.查找，S_BOX，进行置换
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
	//4.output经过置换函数P
	bitset<32> temp = output;
	for (int i = 0; i<32; i++)
		output[31 - i] = temp[32 - P[i]];
	return output;
}

/**
*  对56位密钥的前后部分进行左移
*/
bitset<28> leftShift(bitset<28> k, int shift) {
	bitset<28> tmp = k;
	for (int i = 27; i >= 0; --i)
	{
		if (i - shift<0)
			k[i] = tmp[i - shift + 28];
		else
			k[i] = tmp[i - shift];//为了实现循环左移最后几位为 正确值 
	}

	return k;
}

/*
*  生成16个48位的子密钥
*/
void generateKeys() {
	bitset<56> Key;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;
	//去掉8位的奇偶性，将64位密钥改为56位
	for (int i = 0; i<56; i++)
		Key[55 - i] = key[64 - PC_1[i]];
	//生成子密钥，保存在subKey[16]中 
	for (int round = 0; round<16; round++) {
		for (int i = 28; i<56; i++)//大端机实际上前28位，在存储中是后28位 
			left[i - 28] = Key[i];
		for (int i = 0; i<28; i++)
			right[i] = Key[i];
		//左移
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
*  将char字符转为二进制
*/
bitset<64> charToBitset(const char s[8]) {
	bitset<64> bits;
	for (int i = 0; i<8; i++)
		for (int j = 0; j<8; ++j)
			bits[i * 8 + j] = ((s[i] >> j) & 1);
	return bits;
}



/**
* DES加密
*/
bitset<64> encrypt(bitset<64> &plain) {
	bitset<64> cipher;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	//1.初始置换IP
	for (int i = 0; i<64; i++)
		currentBits[63 - i] = plain[64 - IP[i]];
	//2.获取Li和Ri 
	for (int i = 32; i<64; i++)
		left[i - 32] = currentBits[i];
	for (int i = 0; i<32; i++)
		right[i] = currentBits[i];
	// 3.共16轮迭代	
	for (int round = 0; round<16; round++) {
		newLeft = right;
		right = left ^ f(right, subKey[round]);
		left = newLeft;
	}
	//4.合并L16和R16，注意合并为 R16L16	
	for (int i = 0; i<32; i++)
		cipher[i] = left[i];
	for (int i = 32; i<64; i++)
		cipher[i] = right[i - 32];
	//5.结尾置换IP-1	
	currentBits = cipher;
	for (int i = 0; i<64; i++)
		cipher[63 - i] = currentBits[64 - IP_1[i]];
	//返回密文	
	return cipher;
}

/**
*  DES解密
*/
bitset<64> decrypt(bitset<64>& cipher) {
	bitset<64> plain;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	// 第一步：初始置换IP	
	for (int i = 0; i<64; i++)
		currentBits[63 - i] = cipher[64 - IP[i]];
	// 第二步：获取 Li 和 Ri	
	for (int i = 32; i<64; i++)
		left[i - 32] = currentBits[i];
	for (int i = 0; i<32; i++)
		right[i] = currentBits[i];
	// 第三步：共16轮迭代（子密钥逆序应用）	
	for (int round = 0; round<16; round++) {
		newLeft = right;
		right = left ^ f(right, subKey[15 - round]);
		left = newLeft;
	}
	// 第四步：合并L16和R16，注意合并为 R16L16	
	for (int i = 0; i<32; i++)
		plain[i] = left[i];
	for (int i = 32; i<64; i++)
		plain[i] = right[i - 32];
	// 第五步：结尾置换IP-1	
	currentBits = plain;
	for (int i = 0; i<64; i++)
		plain[63 - i] = currentBits[64 - IP_1[i]];
	// 返回明文	
	return plain;
}

void Cryption_tool::encryption() {
	string k = ui.lineEdit_6->text().toStdString();
	string m = ui.textEdit->toPlainText().toStdString();
	bitset<64> plain = charToBitset(m.c_str());
	key = charToBitset(k.c_str());
	// 生成16个子密钥	               
	generateKeys();
	// 密文写入 a.txt
	bitset<64> cipher = encrypt(plain);
	fstream file1;
	file1.open("./密文.txt", ios::binary | ios::out);
	file1.write((char*)&cipher, sizeof(cipher));
	file1.close();
	ui.textEdit_2->setText((char*)&cipher);
	// 读文件 a.txt	
	bitset<64> temp;
	file1.open("./密文.txt", ios::binary | ios::in);
	file1.read((char*)&temp, sizeof(temp));
	file1.close();
	// 解密，并写入文件 b.txt	
	bitset<64> temp_plain = decrypt(temp);
	file1.open("./明文.txt", ios::binary | ios::out);
	file1.write((char*)&temp_plain, sizeof(temp_plain));
	file1.close();

}
void Cryption_tool::decryption() {
	string k = ui.lineEdit_6->text().toStdString();
	string m = ui.textEdit_2->toPlainText().toStdString();
	bitset<64> plain = charToBitset(m.c_str());
	key = charToBitset(k.c_str());
	// 生成16个子密钥	               
	generateKeys();
	// 密文写入 a.txt
	bitset<64> mingwen = decrypt(plain);
	ui.textEdit->setText((char*)&mingwen);
}